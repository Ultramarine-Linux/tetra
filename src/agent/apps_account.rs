//! The `ultramarine-apps` service account that user apps run under.
//!
//! Every app a user installs is a rootless Quadlet of this one system
//! account (`systemd/tetra.sysusers.conf`): its units live in
//! `~ultramarine-apps/.config/containers/systemd`, its companion files and
//! manifests in `~ultramarine-apps/.local/share/tetra/quadlets`, and its
//! services in the account's user manager, which lingers so they run without
//! a login. Rootful Quadlets are kept for real system services (`scope:
//! "system"`).
//!
//! Tetra writes the account's files as root and hands them to the account
//! ([`Owner`]). Since the account (and so any app container's root) owns
//! that tree, nothing below the home is used by path: every operation goes
//! through [`Tree`](crate::agent::tree::Tree), which resolves paths from the
//! home's descriptor with `openat2` and never follows a symlink, and
//! ownership and modes are set with `fchown`/`fchmod` on open descriptors.
//!
//! `systemd-sysusers` does not allocate subordinate UIDs and GIDs, which
//! rootless Podman needs, so [`AppsAccount::provision`] adds a free range
//! with `usermod --add-subuids/--add-subgids` the first time an app is
//! converged, enables lingering, and gives the account's container storage
//! the labels of `/var/lib/containers/storage`.

use std::{os::fd::BorrowedFd, path::Component, sync::Arc};

use nix::unistd::User;

use crate::agent::{module_support::Commands, tree::Tree};
use crate::prelude::*;

/// The account user apps run as.
pub const APPS_USER: &str = "ultramarine-apps";
/// Fixed UID and GID of [`APPS_USER`] (`systemd/tetra.sysusers.conf`).
pub const APPS_UID: u32 = 242;
/// Home of [`APPS_USER`], used when the account does not exist (yet).
pub const APPS_HOME: &str = "/var/lib/ultramarine-apps";
/// `systemctl --user -M` target for the account's user manager.
pub const SYSTEMCTL_MACHINE: &str = "ultramarine-apps@";

/// Quadlet units, relative to the home (what rootless Quadlet scans).
const QUADLET_DIR: &str = ".config/containers/systemd";
/// Companion files and app manifests, relative to the home.
const DATA_DIR: &str = ".local/share/tetra/quadlets";
/// Rootless Podman's storage, relative to the home.
const STORAGE_DIR: &str = ".local/share/containers/storage";
/// Rootful storage, whose labels the account's storage gets.
const SYSTEM_STORAGE: &str = "/var/lib/containers/storage";
/// Records that the account's storage got [`SYSTEM_STORAGE`]'s labels (the
/// equivalence rule was added and `restorecon` succeeded). Root's, unlike
/// anything in the account's home.
const STORAGE_LABELS_STAMP: &str = "/var/lib/tetra/apps-storage-labels";

/// Directories that are never the account's home: handing one to the
/// account would give it the system.
const SYSTEM_DIRS: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/mnt",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/var/cache",
    "/var/home",
    "/var/lib",
    "/var/lib/containers",
    "/var/lib/systemd",
    "/var/log",
    "/var/mnt",
    "/var/opt",
    "/var/roothome",
    "/var/spool",
    "/var/srv",
    "/var/tmp",
];
/// Trees no home is below.
const SYSTEM_TREES: &[&str] = &[
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/sys",
    "/usr",
    "/var/lib/tetra",
];

/// Fedora's `SUB_UID_MIN`/`SUB_GID_MIN` (`/etc/login.defs`).
const SUBID_MIN: u64 = 524_288;
/// Fedora's `SUB_UID_MAX`/`SUB_GID_MAX`.
const SUBID_MAX: u64 = 600_100_000;
/// Fedora's `SUB_UID_COUNT`/`SUB_GID_COUNT`: one full 16-bit namespace.
const SUBID_COUNT: u64 = 65_536;

/// Warn when the apps account does not have its fixed UID and GID.
///
/// That happens on a host where `ultramarine-apps` existed before the IDs
/// were fixed; apps still work, but files restored from another host (or a
/// Quadlet that names the UID) would not match.
pub fn check_apps_account() {
    match User::from_name(APPS_USER) {
        Ok(Some(user)) if user.uid.as_raw() == APPS_UID && user.gid.as_raw() == APPS_UID => {}
        Ok(Some(user)) => eprintln!(
            "warning: account `{APPS_USER}` has UID {} and GID {}, expected {APPS_UID}; \
             apps still run, but their files will not match other hosts",
            user.uid, user.gid
        ),
        Ok(None) => eprintln!(
            "warning: account `{APPS_USER}` does not exist; apps in the `apps` scope cannot be \
             installed until systemd-sysusers creates it"
        ),
        Err(error) => eprintln!("warning: cannot look up account `{APPS_USER}`: {error}"),
    }
}

/// The account's IDs and home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppsAccount {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

impl AppsAccount {
    /// The account from the user database, if it exists.
    ///
    /// # Errors
    /// Fails when the user database cannot be read.
    pub fn lookup() -> Result<Option<Self>> {
        Ok(User::from_name(APPS_USER)
            .with_context(|| format!("failed to look up `{APPS_USER}`"))?
            .map(|user| Self {
                uid: user.uid.as_raw(),
                gid: user.gid.as_raw(),
                home: user.dir,
            }))
    }

    /// The account, or [`expected`](Self::expected) when it does not exist
    /// (paths for listings and dry runs).
    #[must_use]
    pub fn resolve() -> Self {
        Self::lookup().ok().flatten().unwrap_or_else(Self::expected)
    }

    /// The account as `tetra.sysusers.conf` declares it.
    #[must_use]
    pub fn expected() -> Self {
        Self {
            uid: APPS_UID,
            gid: APPS_UID,
            home: PathBuf::from(APPS_HOME),
        }
    }

    /// The account, which must exist.
    ///
    /// # Errors
    /// Fails when it does not.
    pub fn require() -> Result<Self> {
        Self::lookup()?.with_context(|| {
            format!(
                "account `{APPS_USER}` does not exist; run `systemd-sysusers` \
                 (tetra.sysusers.conf) to create it"
            )
        })
    }

    /// Where rootless Quadlet looks for the account's units.
    #[must_use]
    pub fn quadlet_dir(&self) -> PathBuf {
        self.home.join(QUADLET_DIR)
    }

    /// The data root of companion files and app manifests.
    #[must_use]
    pub fn data_dir(&self) -> PathBuf {
        self.home.join(DATA_DIR)
    }

    /// Rootless Podman's storage.
    #[must_use]
    pub fn storage_dir(&self) -> PathBuf {
        self.home.join(STORAGE_DIR)
    }

    /// `XDG_RUNTIME_DIR` of the account's user manager.
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        runtime_dir(self.uid)
    }

    /// Prepare the host to run the account's services, recording what ran
    /// (or would, on a dry run) in `commands`:
    ///
    /// 1. subordinate UIDs and GIDs, when `/etc/subuid`/`/etc/subgid` have
    ///    none for the account (`usermod --add-subuids/--add-subgids`);
    /// 2. lingering, so the user manager runs from boot without a login
    ///    (`loginctl enable-linger`), then `systemctl start user@<uid>`, so
    ///    the manager is up before Tetra talks to it;
    /// 3. on SELinux hosts, the labels of rootful storage for the account's
    ///    storage (`semanage fcontext -a -e`, then `restorecon -R`, see
    ///    [`label_storage`](Self::label_storage)).
    ///
    /// Each step is skipped when the host already has it, so this is cheap
    /// to repeat. Directories made in the home are handed to `owner`.
    ///
    /// # Errors
    /// Fails when a host file cannot be read, no free subordinate range is
    /// left, the home is refused, or a command fails.
    pub fn provision(
        &self,
        host: &HostPaths,
        owner: Option<Owner>,
        commands: &mut Commands<'_>,
    ) -> Result<()> {
        let mut usermod = Vec::new();
        for (flag, path) in [
            ("--add-subuids", &host.subuid),
            ("--add-subgids", &host.subgid),
        ] {
            let ranges = read_or_empty(path)?;
            if has_subids(&ranges, APPS_USER, self.uid) {
                continue;
            }
            let start = free_subid_range(&ranges).with_context(|| {
                format!(
                    "no free subordinate range of {SUBID_COUNT} IDs in `{}`",
                    path.display()
                )
            })?;
            let end = start.saturating_add(SUBID_COUNT - 1);
            usermod.extend([flag.to_owned(), format!("{start}-{end}")]);
        }
        if !usermod.is_empty() {
            usermod.push(APPS_USER.to_owned());
            let args: Vec<&str> = usermod.iter().map(String::as_str).collect();
            commands.run("usermod", &args)?;
        }

        if !host.linger_dir.join(APPS_USER).exists() {
            commands.run("loginctl", &["enable-linger", APPS_USER])?;
        }
        let manager = format!("user@{}.service", self.uid);
        commands.run("systemctl", &["start", &manager])?;

        if let Some(subs) = &host.selinux_subs {
            self.label_storage(subs, &host.storage_labels_stamp, owner, commands)?;
        }
        Ok(())
    }

    /// Give the account's storage the labels of rootful storage, unless
    /// `stamp` records that this was done: add the equivalence rule to the
    /// policy (unless `subs` already has it), create the storage (rootless
    /// Podman would only make it on first use, and `restorecon` fails on a
    /// missing path), relabel it with `restorecon -R`, and write `stamp`.
    /// The stamp, not the rule, decides, so a relabel that failed is
    /// retried on the next converge. A dry run only plans the commands.
    fn label_storage(
        &self,
        subs: &Path,
        stamp: &Path,
        owner: Option<Owner>,
        commands: &mut Commands<'_>,
    ) -> Result<()> {
        check_home(&self.home)?;
        let storage = self.storage_dir();
        let storage_arg = storage
            .to_str()
            .with_context(|| format!("`{}` is not valid UTF-8", storage.display()))?;
        let labeled = format!("{storage_arg} {SYSTEM_STORAGE}\n");
        // Unreadable (missing, or not root on a dry run) means not done yet.
        if fs::read_to_string(stamp).is_ok_and(|contents| contents == labeled) {
            return Ok(());
        }
        if !has_equivalence(&read_or_empty(subs)?, storage_arg, SYSTEM_STORAGE) {
            commands.run(
                "semanage",
                &["fcontext", "-a", "-e", SYSTEM_STORAGE, storage_arg],
            )?;
        }
        if !commands.dry_run() {
            Tree::new(&storage, Some(&self.home), owner).create_dir(&storage)?;
        }
        commands.run("restorecon", &["-R", storage_arg])?;
        if !commands.dry_run() {
            let dir = stamp
                .parent()
                .with_context(|| format!("`{}` has no directory", stamp.display()))?;
            Tree::trusted(dir).write(stamp, labeled.as_bytes(), 0o644)?;
        }
        Ok(())
    }
}

/// Refuse a home that cannot be the account's.
///
/// That is one that is not an absolute plain path, or is (or is below) a
/// system directory, such as `/` from a broken account database: Tetra
/// hands the home to the account.
///
/// # Errors
/// Fails when `home` is refused.
pub fn check_home(home: &Path) -> Result<()> {
    let refuse = |why: &str| {
        anyhow::anyhow!(
            "refusing `{}` as the home of `{APPS_USER}`: {why}",
            home.display()
        )
    };
    let mut components = home.components();
    if components.next() != Some(Component::RootDir)
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(refuse("it is not an absolute path without `.` or `..`"));
    }
    if SYSTEM_DIRS.iter().any(|dir| home == Path::new(dir))
        || SYSTEM_TREES.iter().any(|tree| home.starts_with(tree))
    {
        return Err(refuse("it is a system directory"));
    }
    Ok(())
}

/// `/run/user/<uid>`, a user manager's `XDG_RUNTIME_DIR`.
#[must_use]
pub fn runtime_dir(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}"))
}

/// Host files [`AppsAccount::provision`] reads, so tests can point them at
/// a temporary directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    pub subuid: PathBuf,
    pub subgid: PathBuf,
    /// logind's linger flags (`/var/lib/systemd/linger/<user>`).
    pub linger_dir: PathBuf,
    /// The policy's local file-context equivalences (`semanage fcontext
    /// -a -e`), or `None` on a host without SELinux.
    pub selinux_subs: Option<PathBuf>,
    /// Where Tetra records that the account's storage was labeled.
    pub storage_labels_stamp: PathBuf,
}

impl HostPaths {
    /// This host's.
    #[must_use]
    pub fn system() -> Self {
        let selinux = Path::new("/sys/fs/selinux/enforce").exists();
        Self {
            subuid: PathBuf::from("/etc/subuid"),
            subgid: PathBuf::from("/etc/subgid"),
            linger_dir: PathBuf::from("/var/lib/systemd/linger"),
            selinux_subs: selinux.then(|| {
                Path::new("/etc/selinux")
                    .join(selinux_policy_type())
                    .join("contexts/files/file_contexts.subs")
            }),
            storage_labels_stamp: PathBuf::from(STORAGE_LABELS_STAMP),
        }
    }
}

/// `SELINUXTYPE` from `/etc/selinux/config` (`targeted` by default).
fn selinux_policy_type() -> String {
    fs::read_to_string("/etc/selinux/config")
        .ok()
        .and_then(|config| {
            config.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("SELINUXTYPE=")
                    .map(|value| value.trim().to_owned())
            })
        })
        .filter(|value| !value.is_empty() && !value.contains('/'))
        .unwrap_or_else(|| "targeted".to_owned())
}

fn read_or_empty(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).with_context(|| format!("failed to read `{}`", path.display())),
    }
}

/// The `(start, count)` ranges of a `/etc/subuid`-style file.
fn subid_ranges(contents: &str) -> impl Iterator<Item = (&str, u64, u64)> {
    contents.lines().filter_map(|line| {
        let mut fields = line.trim().split(':');
        let owner = fields.next()?;
        let start = fields.next()?.parse().ok()?;
        let count = fields.next()?.parse().ok()?;
        Some((owner, start, count))
    })
}

/// Whether the file gives `name` (or its UID) a range.
fn has_subids(contents: &str, name: &str, uid: u32) -> bool {
    let uid = uid.to_string();
    subid_ranges(contents).any(|(owner, _, count)| (owner == name || owner == uid) && count > 0)
}

/// The first free range of [`SUBID_COUNT`] IDs within Fedora's limits, as
/// `useradd` would pick it.
fn free_subid_range(contents: &str) -> Option<u64> {
    let mut taken: Vec<(u64, u64)> = subid_ranges(contents)
        .map(|(_, start, count)| (start, start.saturating_add(count)))
        .collect();
    taken.sort_unstable();
    let mut candidate = SUBID_MIN;
    for (start, end) in taken {
        if candidate.saturating_add(SUBID_COUNT) <= start {
            break;
        }
        candidate = candidate.max(end);
    }
    (candidate.saturating_add(SUBID_COUNT - 1) <= SUBID_MAX).then_some(candidate)
}

/// Whether `file_contexts.subs` maps `path` to `target`.
fn has_equivalence(subs: &str, path: &str, target: &str) -> bool {
    subs.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some(path) && fields.next() == Some(target)
    })
}

type ChownFn = dyn Fn(BorrowedFd<'_>, &Path, u32, u32) -> io::Result<()> + Send + Sync;

/// Hands files and directories Tetra creates (as root) to the apps account,
/// through their open descriptors ([`Tree`](crate::agent::tree::Tree)).
#[derive(Clone)]
pub struct Owner {
    uid: u32,
    gid: u32,
    chown: Arc<ChownFn>,
    /// Whether a home of Tetra's own that it did not just create may be
    /// taken over: only for tests, whose fake chown leaves the home theirs.
    adopt_existing: bool,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Owner")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish_non_exhaustive()
    }
}

impl Owner {
    /// Change ownership with `fchown`.
    #[must_use]
    pub fn new(account: &AppsAccount) -> Self {
        Self::with_chown(account, |fd, _, uid, gid| {
            rustix::fs::fchown(
                fd,
                Some(rustix::fs::Uid::from_raw(uid)),
                Some(rustix::fs::Gid::from_raw(gid)),
            )
            .map_err(io::Error::from)
        })
    }

    /// Change ownership with `chown`, which gets the open file and its path
    /// (for messages; a fake, in tests).
    pub fn with_chown<F>(account: &AppsAccount, chown: F) -> Self
    where
        F: Fn(BorrowedFd<'_>, &Path, u32, u32) -> io::Result<()> + Send + Sync + 'static,
    {
        Self {
            uid: account.uid,
            gid: account.gid,
            chown: Arc::new(chown),
            adopt_existing: false,
        }
    }

    /// Also take over a home of Tetra's own that it did not just create
    /// (tests: a fake chown never hands the home over, so it stays theirs
    /// after the first write).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn adopting_existing_homes(mut self) -> Self {
        self.adopt_existing = true;
        self
    }

    /// The owner of files written for the apps scope: the account, when
    /// Tetra runs as root and this is no dry run. Without root (tests,
    /// development) nothing can be given away, and files stay the caller's.
    ///
    /// # Errors
    /// Fails when Tetra is root and the account does not exist.
    pub fn for_apps(dry_run: bool) -> Result<Option<Self>> {
        if dry_run || !nix::unistd::geteuid().is_root() {
            return Ok(None);
        }
        Ok(Some(Self::new(&AppsAccount::require()?)))
    }

    /// Give the open file or directory `fd` (at `path`) to the account,
    /// unless it already belongs to it.
    ///
    /// # Errors
    /// Fails when `fd` cannot be inspected or given away.
    pub fn claim(&self, fd: BorrowedFd<'_>, path: &Path) -> Result<()> {
        let stat = rustix::fs::fstat(fd)
            .map_err(io::Error::from)
            .with_context(|| format!("failed to inspect `{}`", path.display()))?;
        if stat.st_uid != self.uid || stat.st_gid != self.gid {
            (self.chown)(fd, path, self.uid, self.gid)
                .with_context(|| format!("failed to give `{}` to `{APPS_USER}`", path.display()))?;
        }
        Ok(())
    }

    /// Whether a home owned by `uid` may be written to and handed to the
    /// account: it must already be the account's, or be one Tetra just
    /// `created` (so its own). Anyone else's directory, root's included, is
    /// refused rather than given away, in case the account database points
    /// the home somewhere it should not (`systemd-tmpfiles` creates the home
    /// as the account's, so a root-owned one is not the expected home).
    #[must_use]
    pub fn may_own_home(&self, uid: u32, created: bool) -> bool {
        uid == self.uid
            || ((created || self.adopt_existing) && uid == nix::unistd::geteuid().as_raw())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An owner whose chown records the paths it was asked to give away,
    /// relative to `home`.
    pub fn recording_owner(home: &Path) -> (Owner, Arc<std::sync::Mutex<Vec<String>>>) {
        let chowned = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&chowned);
        let base = home.to_path_buf();
        let account = AppsAccount {
            // Never the test's own IDs, so every entry is recorded.
            uid: u32::MAX - 1,
            gid: u32::MAX - 1,
            home: home.to_path_buf(),
        };
        let owner = Owner::with_chown(&account, move |_, path, uid, gid| {
            assert_eq!((uid, gid), (u32::MAX - 1, u32::MAX - 1));
            let relative = path.strip_prefix(&base).unwrap_or(path);
            record
                .lock()
                .unwrap()
                .push(relative.to_string_lossy().into_owned());
            Ok(())
        })
        .adopting_existing_homes();
        (owner, chowned)
    }

    #[test]
    fn paths_live_in_the_accounts_home() {
        let account = AppsAccount::expected();
        assert_eq!(account.uid, 242);
        assert_eq!(
            account.quadlet_dir(),
            Path::new("/var/lib/ultramarine-apps/.config/containers/systemd")
        );
        assert_eq!(
            account.data_dir(),
            Path::new("/var/lib/ultramarine-apps/.local/share/tetra/quadlets")
        );
        assert_eq!(account.runtime_dir(), Path::new("/run/user/242"));
    }

    #[test]
    fn sysusers_declares_the_fixed_apps_account() {
        let sysusers = include_str!("../../systemd/tetra.sysusers.conf");
        let line = sysusers
            .lines()
            .find(|line| line.starts_with(&format!("u {APPS_USER} ")))
            .unwrap();
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields[2], format!("{APPS_UID}:{APPS_UID}"));
        assert!(line.ends_with(APPS_HOME), "{line}");
        let tmpfiles = include_str!("../../systemd/tetra.tmpfiles.conf");
        assert!(tmpfiles.contains(&format!("d {APPS_HOME} 0700 {APPS_USER} {APPS_USER}")));
        assert!(tmpfiles.contains(&format!("f /var/lib/systemd/linger/{APPS_USER}")));
    }

    #[test]
    fn finds_existing_subids_by_name_or_uid() {
        let ranges = "cypress:524288:65536\n242:589824:65536\n";
        assert!(has_subids(ranges, APPS_USER, 242));
        assert!(!has_subids(ranges, APPS_USER, 243));
        assert!(has_subids("ultramarine-apps:1000000:65536\n", APPS_USER, 1));
        assert!(!has_subids("ultramarine-apps:1000000:0\n", APPS_USER, 1));
    }

    #[test]
    fn picks_the_first_free_subid_range() {
        assert_eq!(free_subid_range(""), Some(524_288));
        assert_eq!(
            free_subid_range("a:524288:65536\nb:589824:65536\n"),
            Some(655_360)
        );
        // A gap big enough is reused; one too small is skipped.
        assert_eq!(
            free_subid_range("b:655360:65536\n"),
            Some(524_288),
            "the gap below b"
        );
        assert_eq!(
            free_subid_range("a:524288:65536\nc:600000:65536\n"),
            Some(665_536)
        );
        // Ranges below the minimum do not matter.
        assert_eq!(free_subid_range("x:100000:65536\n"), Some(524_288));
        // Nothing fits below the maximum.
        assert_eq!(free_subid_range("x:524288:600000000\n"), None);
    }

    #[test]
    fn reads_equivalences() {
        let subs = "/var/lib/ultramarine-apps/.local/share/containers/storage /var/lib/containers/storage\n";
        assert!(has_equivalence(
            subs,
            "/var/lib/ultramarine-apps/.local/share/containers/storage",
            SYSTEM_STORAGE
        ));
        assert!(!has_equivalence(subs, "/srv", SYSTEM_STORAGE));
    }

    fn host(dir: &Path, selinux: bool) -> HostPaths {
        HostPaths {
            subuid: dir.join("subuid"),
            subgid: dir.join("subgid"),
            linger_dir: dir.join("linger"),
            selinux_subs: selinux.then(|| dir.join("file_contexts.subs")),
            storage_labels_stamp: dir.join("tetra/apps-storage-labels"),
        }
    }

    fn planned(commands: &Commands<'_>) -> Vec<String> {
        commands
            .done
            .iter()
            .map(|command| command["command"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn plans_subids_linger_and_labels() {
        let dir = tempfile::tempdir().unwrap();
        let host = host(dir.path(), true);
        fs::write(&host.subuid, "cypress:524288:65536\n").unwrap();
        let account = AppsAccount::expected();

        let mut commands = Commands::fake(true, "");
        account.provision(&host, None, &mut commands).unwrap();
        assert_eq!(
            planned(&commands),
            [
                "usermod --add-subuids 589824-655359 --add-subgids 524288-589823 ultramarine-apps",
                "loginctl enable-linger ultramarine-apps",
                "systemctl start user@242.service",
                "semanage fcontext -a -e /var/lib/containers/storage \
                 /var/lib/ultramarine-apps/.local/share/containers/storage",
                "restorecon -R /var/lib/ultramarine-apps/.local/share/containers/storage",
            ]
        );
        // A dry run changes nothing.
        assert!(!host.storage_labels_stamp.exists());

        // Without SELinux there is nothing to label.
        let mut commands = Commands::fake(true, "");
        let mut host = host;
        host.selinux_subs = None;
        account.provision(&host, None, &mut commands).unwrap();
        assert_eq!(
            planned(&commands),
            [
                "usermod --add-subuids 589824-655359 --add-subgids 524288-589823 ultramarine-apps",
                "loginctl enable-linger ultramarine-apps",
                "systemctl start user@242.service",
            ]
        );
    }

    #[test]
    fn labels_the_storage_until_a_relabel_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let host = host(dir.path(), true);
        fs::write(&host.subuid, "ultramarine-apps:589824:65536\n").unwrap();
        fs::write(&host.subgid, "242:524288:65536\n").unwrap();
        fs::create_dir_all(&host.linger_dir).unwrap();
        fs::write(host.linger_dir.join(APPS_USER), "").unwrap();
        let home = dir.path().join("apps");
        let (owner, chowned) = recording_owner(&home);
        let account = AppsAccount {
            home,
            ..AppsAccount::expected()
        };
        let storage = account.storage_dir();
        let semanage = format!(
            "semanage fcontext -a -e /var/lib/containers/storage {}",
            storage.display()
        );
        let restorecon = format!("restorecon -R {}", storage.display());
        // `restorecon` fails on a missing path, as the real one does.
        let runner = |failing: bool| {
            let storage = storage.clone();
            move |program: &str, args: &[&str]| {
                let command = crate::agent::module_support::command_display(program, args);
                ensure!(
                    program != "restorecon" || (storage.is_dir() && !failing),
                    "`{command}` failed"
                );
                Ok(crate::agent::module_support::CommandResult {
                    command,
                    status: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    dry_run: false,
                })
            }
        };

        // The rule is added and the storage made (and handed over) before
        // the relabel; the relabel fails, so nothing is recorded.
        let mut commands = Commands::with_runner(false, runner(true));
        account
            .provision(&host, Some(owner.clone()), &mut commands)
            .unwrap_err();
        assert_eq!(
            planned(&commands),
            ["systemctl start user@242.service", &semanage, &restorecon]
        );
        assert!(storage.is_dir());
        assert_eq!(
            *chowned.lock().unwrap(),
            [
                "",
                ".local",
                ".local/share",
                ".local/share/containers",
                ".local/share/containers/storage"
            ]
        );
        assert!(!host.storage_labels_stamp.exists());

        // The rule is there now, but the storage still needs its labels.
        fs::write(
            host.selinux_subs.as_ref().unwrap(),
            format!("{} /var/lib/containers/storage\n", storage.display()),
        )
        .unwrap();
        let mut commands = Commands::with_runner(false, runner(false));
        account
            .provision(&host, Some(owner.clone()), &mut commands)
            .unwrap();
        assert_eq!(
            planned(&commands),
            ["systemctl start user@242.service", &restorecon]
        );
        assert_eq!(
            fs::read_to_string(&host.storage_labels_stamp).unwrap(),
            format!("{} /var/lib/containers/storage\n", storage.display())
        );

        // Done once, then never again.
        let mut commands = Commands::with_runner(false, runner(true));
        account
            .provision(&host, Some(owner.clone()), &mut commands)
            .unwrap();
        assert_eq!(planned(&commands), ["systemctl start user@242.service"]);

        // A stamp for another storage does not count.
        fs::write(
            &host.storage_labels_stamp,
            "/elsewhere /var/lib/containers/storage\n",
        )
        .unwrap();
        let mut commands = Commands::with_runner(false, runner(false));
        account
            .provision(&host, Some(owner), &mut commands)
            .unwrap();
        assert_eq!(
            planned(&commands),
            ["systemctl start user@242.service", &restorecon]
        );
    }

    #[test]
    fn refuses_system_directories_as_the_home() {
        for home in [
            "/",
            "/var",
            "/var/lib",
            "/var/lib/",
            "/usr",
            "/usr/local/apps",
            "/etc/apps",
            "/root",
            "/var/lib/tetra",
            "/var/lib/tetra/apps",
            "var/lib/ultramarine-apps",
            "/var/lib/../lib",
            "/var/lib/./apps/..",
        ] {
            check_home(Path::new(home)).unwrap_err();
        }
        for home in [APPS_HOME, "/var/lib/apps", "/srv/apps", "/home/apps"] {
            check_home(Path::new(home)).unwrap();
        }

        // Nothing is labeled in a refused home.
        let dir = tempfile::tempdir().unwrap();
        let account = AppsAccount {
            home: PathBuf::from("/"),
            ..AppsAccount::expected()
        };
        let mut commands = Commands::fake(true, "");
        fs::write(dir.path().join("subuid"), "242:589824:65536\n").unwrap();
        fs::write(dir.path().join("subgid"), "242:589824:65536\n").unwrap();
        account
            .provision(&host(dir.path(), true), None, &mut commands)
            .unwrap_err();
        assert!(
            !planned(&commands)
                .iter()
                .any(|command| command.starts_with("semanage"))
        );
    }

    #[test]
    fn only_a_home_tetra_just_created_may_be_its_own() {
        let account = AppsAccount {
            uid: u32::MAX - 1,
            gid: u32::MAX - 1,
            home: PathBuf::from("/nonexistent"),
        };
        let owner = Owner::with_chown(&account, |_, _, _, _| Ok(()));
        let me = nix::unistd::geteuid().as_raw();
        assert!(owner.may_own_home(u32::MAX - 1, false));
        assert!(owner.may_own_home(me, true));
        assert!(
            !owner.may_own_home(me, false),
            "an existing home of Tetra's own"
        );
        let stranger = me.wrapping_add(1);
        if stranger != u32::MAX - 1 {
            assert!(!owner.may_own_home(stranger, true));
            assert!(!owner.may_own_home(stranger, false));
        }
    }
}
