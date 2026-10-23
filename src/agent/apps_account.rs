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
//! Tetra writes the account's files as root and then hands them to the
//! account. Since the account (and so any app container's root) owns that
//! tree, every directory from the home down is checked for symlinks first,
//! and ownership is changed with `lchown`, which never follows one.
//!
//! `systemd-sysusers` does not allocate subordinate UIDs and GIDs, which
//! rootless Podman needs, so [`AppsAccount::provision`] adds a free range
//! with `usermod --add-subuids/--add-subgids` the first time an app is
//! converged, enables lingering, and gives the account's container storage
//! the labels of `/var/lib/containers/storage`.

use std::{
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _},
    sync::Arc,
};

use nix::unistd::User;

use crate::agent::module_support::{Commands, write_under};
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
    ///    storage (`semanage fcontext -a -e`, then `restorecon`).
    ///
    /// Each step is skipped when the host already has it, so this is cheap
    /// to repeat.
    ///
    /// # Errors
    /// Fails when a host file cannot be read, no free subordinate range is
    /// left, or a command fails.
    pub fn provision(&self, host: &HostPaths, commands: &mut Commands<'_>) -> Result<()> {
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
            let storage = self.storage_dir();
            let storage = storage.to_string_lossy();
            if !has_equivalence(&read_or_empty(subs)?, &storage, SYSTEM_STORAGE) {
                commands.run(
                    "semanage",
                    &["fcontext", "-a", "-e", SYSTEM_STORAGE, &storage],
                )?;
                commands.run("restorecon", &["-R", &storage])?;
            }
        }
        Ok(())
    }
}

/// Refuse `dir` when a directory between `home` and it is a symlink, so a
/// link the account planted cannot point a root read, write or removal
/// elsewhere. Components that do not exist yet are fine.
///
/// # Errors
/// Fails on a symlink, or when a component cannot be inspected.
pub fn check_no_symlinks(home: &Path, dir: &Path) -> Result<()> {
    let Ok(below) = dir.strip_prefix(home) else {
        return Ok(());
    };
    let mut current = home.to_path_buf();
    for component in std::iter::once(None).chain(below.components().map(Some)) {
        if let Some(component) = component {
            current.push(component);
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "`{}` is a symlink; refusing to follow it",
                    current.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect `{}`", current.display()));
            }
        }
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

type ChownFn = dyn Fn(&Path, u32, u32) -> io::Result<()> + Send + Sync;

/// Hands files Tetra wrote (as root) to the apps account.
#[derive(Clone)]
pub struct Owner {
    uid: u32,
    gid: u32,
    /// The account's home: directories from here down are the account's.
    home: PathBuf,
    chown: Arc<ChownFn>,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Owner")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Owner {
    /// Change ownership with `lchown`.
    #[must_use]
    pub fn new(account: &AppsAccount) -> Self {
        Self::with_chown(account, |path, uid, gid| {
            std::os::unix::fs::lchown(path, Some(uid), Some(gid))
        })
    }

    /// Change ownership with `chown` (a fake, in tests).
    pub fn with_chown<F>(account: &AppsAccount, chown: F) -> Self
    where
        F: Fn(&Path, u32, u32) -> io::Result<()> + Send + Sync + 'static,
    {
        Self {
            uid: account.uid,
            gid: account.gid,
            home: account.home.clone(),
            chown: Arc::new(chown),
        }
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

    /// Create `dir` if needed, every directory from the account's home down
    /// to it owned by the account (just `dir` itself, when it is outside
    /// the home). A symlink on the way is refused, since the account could
    /// have planted it to point a root write elsewhere.
    ///
    /// # Errors
    /// Fails on a symlink or non-directory on the way, or when a directory
    /// cannot be created or given away.
    pub fn prepare_dir(&self, dir: &Path) -> Result<()> {
        let Ok(below) = dir.strip_prefix(&self.home) else {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create `{}`", dir.display()))?;
            return self.claim_entry(dir, true);
        };
        // The home itself, then each component below it.
        let mut current = self.home.clone();
        self.make_dir(&current, 0o700)?;
        for component in below.components() {
            let std::path::Component::Normal(component) = component else {
                bail!("`{}` is not a plain path below the home", dir.display());
            };
            current.push(component);
            self.make_dir(&current, 0o755)?;
        }
        Ok(())
    }

    /// Give `path`, just written, to the account, along with the directories
    /// between the account's home and it.
    ///
    /// # Errors
    /// See [`prepare_dir`](Self::prepare_dir).
    pub fn claim(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            self.prepare_dir(parent)?;
        }
        self.claim_entry(path, false)
    }

    fn make_dir(&self, dir: &Path, mode: u32) -> Result<()> {
        match fs::symlink_metadata(dir) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(mode).create(dir) {
                    // The umask may have narrowed the mode.
                    Ok(()) => {
                        use std::os::unix::fs::PermissionsExt as _;
                        fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("failed to create `{}`", dir.display()));
                    }
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect `{}`", dir.display()));
            }
        }
        self.claim_entry(dir, true)
    }

    /// `lchown` one entry unless it already belongs to the account.
    fn claim_entry(&self, path: &Path, directory: bool) -> Result<()> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect `{}`", path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "`{}` is a symlink; refusing to write through it",
            path.display()
        );
        ensure!(
            !directory || metadata.is_dir(),
            "`{}` is not a directory",
            path.display()
        );
        if metadata.uid() != self.uid || metadata.gid() != self.gid {
            (self.chown)(path, self.uid, self.gid)
                .with_context(|| format!("failed to give `{}` to `{APPS_USER}`", path.display()))?;
        }
        Ok(())
    }
}

/// [`write_under`], handing the file (and the directories it needed) to
/// `owner` when there is one. The directories from the owner's home down to
/// `base` are checked before anything is written.
///
/// # Errors
/// Fails when the path is refused, or the write or ownership change fails.
pub fn write_owned(
    base: &Path,
    relative: &str,
    contents: &[u8],
    mode: u32,
    dry_run: bool,
    owner: Option<&Owner>,
) -> Result<PathBuf> {
    let owner = owner.filter(|_| !dry_run);
    if let Some(owner) = owner {
        owner.prepare_dir(base)?;
    }
    let path = write_under(base, relative, contents, mode, dry_run)?;
    if let Some(owner) = owner {
        owner.claim(&path)?;
    }
    Ok(path)
}

/// Create `dir` and its parents (owned by `owner`, when there is one),
/// unless `dry_run`.
///
/// # Errors
/// Fails when a directory cannot be created or given away.
pub fn create_dir_owned(dir: &Path, dry_run: bool, owner: Option<&Owner>) -> Result<()> {
    match owner {
        _ if dry_run => Ok(()),
        Some(owner) => owner.prepare_dir(dir),
        None => {
            fs::create_dir_all(dir).with_context(|| format!("failed to create `{}`", dir.display()))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use super::*;

    /// An owner rooted at `home` whose chown records the paths it was asked
    /// to give away, relative to `home`.
    pub fn recording_owner(home: &Path) -> (Owner, Arc<Mutex<Vec<String>>>) {
        let chowned = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&chowned);
        let base = home.to_path_buf();
        let account = AppsAccount {
            // Never the test's own IDs, so every entry is recorded.
            uid: u32::MAX - 1,
            gid: u32::MAX - 1,
            home: home.to_path_buf(),
        };
        let owner = Owner::with_chown(&account, move |path, uid, gid| {
            assert_eq!((uid, gid), (u32::MAX - 1, u32::MAX - 1));
            let relative = path.strip_prefix(&base).unwrap_or(path);
            record
                .lock()
                .unwrap()
                .push(relative.to_string_lossy().into_owned());
            Ok(())
        });
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
    fn provisions_subids_linger_and_labels_once() {
        let dir = tempfile::tempdir().unwrap();
        let host = host(dir.path(), true);
        fs::write(&host.subuid, "cypress:524288:65536\n").unwrap();
        let account = AppsAccount::expected();

        let mut commands = Commands::fake(true, "");
        account.provision(&host, &mut commands).unwrap();
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

        // A host that already has everything only gets the manager started.
        fs::write(&host.subuid, "ultramarine-apps:589824:65536\n").unwrap();
        fs::write(&host.subgid, "242:524288:65536\n").unwrap();
        fs::create_dir_all(&host.linger_dir).unwrap();
        fs::write(host.linger_dir.join(APPS_USER), "").unwrap();
        fs::write(
            host.selinux_subs.as_ref().unwrap(),
            "/var/lib/ultramarine-apps/.local/share/containers/storage /var/lib/containers/storage\n",
        )
        .unwrap();
        let mut commands = Commands::fake(false, "");
        account.provision(&host, &mut commands).unwrap();
        assert_eq!(planned(&commands), ["systemctl start user@242.service"]);

        // Without SELinux there is nothing to label.
        let mut commands = Commands::fake(true, "");
        let mut host = host;
        host.selinux_subs = None;
        fs::write(&host.subgid, "").unwrap();
        account.provision(&host, &mut commands).unwrap();
        assert_eq!(
            planned(&commands),
            [
                "usermod --add-subgids 524288-589823 ultramarine-apps",
                "systemctl start user@242.service",
            ]
        );
    }

    #[test]
    fn owner_creates_and_gives_away_the_tree_below_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let (owner, chowned) = recording_owner(&home);
        let quadlets = home.join(".config/containers/systemd");
        owner.prepare_dir(&quadlets).unwrap();
        assert!(quadlets.is_dir());
        assert_eq!(
            *chowned.lock().unwrap(),
            [
                "",
                ".config",
                ".config/containers",
                ".config/containers/systemd"
            ]
        );
        let mode = |path: &Path| {
            use std::os::unix::fs::PermissionsExt as _;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(&quadlets), 0o755);

        chowned.lock().unwrap().clear();
        let unit = quadlets.join("app.container");
        fs::write(&unit, "[Container]\n").unwrap();
        owner.claim(&unit).unwrap();
        assert!(
            chowned
                .lock()
                .unwrap()
                .ends_with(&[".config/containers/systemd/app.container".to_owned()])
        );
    }

    #[test]
    fn owner_refuses_symlinks_below_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let elsewhere = dir.path().join("etc");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".config")).unwrap();
        let (owner, chowned) = recording_owner(&home);
        let error = owner
            .prepare_dir(&home.join(".config/containers/systemd"))
            .unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(!elsewhere.join("containers").exists());
        assert_eq!(*chowned.lock().unwrap(), [""]);

        let file = home.join("link");
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        owner.claim(&file).unwrap_err();

        check_no_symlinks(&home, &home.join(".config/containers")).unwrap_err();
        check_no_symlinks(&home, &home.join(".local/share")).unwrap();
        check_no_symlinks(&home, &elsewhere).unwrap();
    }
}
