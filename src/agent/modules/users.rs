//! Local user and group management.
//!
//! Wraps the classic shadow-utils CLIs (`useradd`, `usermod`, `userdel`) for
//! account lifecycle, and reads `/etc/passwd` and `/etc/group` directly for
//! listing. Mutating actions honor the shared `dry_run` flag.
//!
//! A few conventions worth knowing:
//! - `useradd` and `usermod` use *different* flag names for the home directory
//!   (`--home-dir` vs `--home`); the arg-building code below mirrors that
//!   difference on purpose.
//! - `set_password` never sees a plaintext password. The caller supplies a
//!   pre-hashed value (`$y$…`, `$6$…`, …) which is passed straight to
//!   `usermod --password`, matching how `/etc/shadow` stores it.
//! - `create`/`update` deliberately omit flags the caller did not set, so
//!   shadow-utils defaults apply for anything left unspecified.
//! - `add_admin` adds a user to `ultramarine-admin`, the group that makes an
//!   account a Tetra administrator. The setup session may only use it while
//!   no administrator exists (checked by the auth service).
//! - `set_authorized_keys` replaces `~name/.ssh/authorized_keys`. The user
//!   owns their home directory, so every step below it is done relative to
//!   directory handles opened with `O_NOFOLLOW`, and the file is renamed into
//!   place: a symlink planted at `.ssh` or `authorized_keys` makes the action
//!   fail or is replaced, never followed.

use std::{
    io::Write as _,
    os::fd::{AsFd, OwnedFd},
};

use nix::{
    errno::Errno,
    fcntl::{AT_FDCWD, OFlag, openat, renameat},
    sys::stat::{Mode, fchmod, mkdirat},
    unistd::{Gid, Uid, UnlinkatFlags, fchown, fsync, unlinkat},
};

use crate::prelude::*;

/// Group whose members are Tetra administrators (with `wheel`).
pub const ADMIN_GROUP: &str = "ultramarine-admin";
/// Most keys `set_authorized_keys` accepts.
const MAX_KEYS: usize = 100;
/// Longest accepted key line (large RSA keys with options fit easily).
const MAX_KEY_LEN: usize = 16 * 1024;
const AUTHORIZED_KEYS: &str = "authorized_keys";

/// Marker type for the users module. Stateless; all behavior lives in the
/// [`Mod`] impl and the static [`INFO`] descriptor.
#[derive(Clone, Copy, Debug)]
pub struct UsersModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "users",
    feature: "users",
    description: "Inspect and manage local users, groups, and account-related configuration.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "list",
        "status",
        "create",
        "update",
        "delete",
        "set_password",
        "set_authorized_keys",
        "add_admin",
        "groups",
    ],
    privileged_actions: &[
        "create",
        "update",
        "delete",
        "set_password",
        "set_authorized_keys",
        "add_admin",
        "groups",
    ],
};

impl Mod for UsersModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    List => Ok(jsonf! { "users": parse_passwd(&read_file("/etc/passwd")?) }),
    Groups => Ok(jsonf! { "groups": parse_group(&read_file("/etc/group")?) }),
    Status { name: String } => crate::cmd!({ &INFO, "status", user } "id" [&payload.name] json),
    Create {
        name: String,
        shell: Option<String>,
        home: Option<String>,
        #[serde(default)]
        system: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        let mut args = Vec::new();
        // `useradd` spells the home flag `--home-dir` (unlike
        // `usermod`'s `--home` below).
        flag!(args payload: system [shell] ["--home-dir" home]);
        args.push(payload.name);
        crate::cmd!((payload.dry_run) { &INFO, "create", user } "useradd" => &args ; json)
    },
    Update {
        name: String,
        shell: Option<String>,
        home: Option<String>,
        groups: Option<Vec<String>>,
        #[serde(default)]
        dry_run: bool,
    } => {
        let mut args = Vec::new();
        flag!(args payload: [shell] [home]);
        if let Some(groups) = payload.groups {
            args.extend(["--groups".into(), groups.join(",")]);
        }
        args.push(payload.name);
        crate::cmd!((payload.dry_run) { &INFO, "update", user } "usermod" => &args ; json)
    },
    Delete {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => crate::cmd!((payload.dry_run) { &INFO, "delete", user } "userdel" [&payload.name] json),
    SetPassword {
        name: String,
        password_hash: String,
        #[serde(default)]
        dry_run: bool,
    } => crate::cmd!((payload.dry_run) { &INFO, "set_password", user } "usermod" ["--password", &payload.password_hash, &payload.name] json),
    SetAuthorizedKeys {
        name: String,
        /// OpenSSH public key lines; an empty list clears the file.
        keys: Vec<String>,
        #[serde(default)]
        dry_run: bool,
    } => {
        let contents = authorized_keys(&payload.keys)?;
        let account = nix::unistd::User::from_name(&payload.name)
            .with_context(|| format!("failed to look up `{}`", payload.name))?
            .with_context(|| format!("no account named `{}`", payload.name))?;
        let path = account.dir.join(".ssh").join(AUTHORIZED_KEYS);
        if !payload.dry_run {
            write_authorized_keys(&account.dir, account.uid, account.gid, contents.as_bytes())?;
        }
        // Default labels (ssh_home_t), so sshd may read the file.
        let selinux = if payload.dry_run || Path::new("/sys/fs/selinux/enforce").exists() {
            let ssh_dir = account.dir.join(".ssh");
            let ssh_dir = ssh_dir.to_string_lossy();
            vec![crate::cmd!((payload.dry_run) "restorecon" ["-R", &*ssh_dir] json)?]
        } else {
            Vec::new()
        };
        Ok(jsonf! {
            payload.name, path,
            "keys": payload.keys.len(),
            "written": !payload.dry_run,
            payload.dry_run, selinux,
        })
    },
    AddAdmin {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => crate::cmd!((payload.dry_run) { &INFO, "add_admin", user } "usermod" ["--append", "--groups", ADMIN_GROUP, &payload.name] json),
});

/// Validate key lines and join them into an `authorized_keys` file.
fn authorized_keys(keys: &[String]) -> Result<String> {
    ensure!(keys.len() <= MAX_KEYS, "at most {MAX_KEYS} keys are accepted");
    let mut contents = String::new();
    for key in keys {
        let key = key.trim();
        ensure!(
            !key.is_empty() && key.len() <= MAX_KEY_LEN,
            "keys must be 1 to {MAX_KEY_LEN} characters"
        );
        // One line each: a newline would add a second, unvalidated entry.
        ensure!(
            !key.chars().any(char::is_control),
            "keys must be single lines without control characters"
        );
        ensure!(
            key.split_whitespace().any(|field| {
                ["ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-sha2-"]
                    .iter()
                    .any(|prefix| field.starts_with(prefix))
            }),
            "`{}` is not an OpenSSH public key",
            key.chars().take(32).collect::<String>()
        );
        contents.push_str(key);
        contents.push('\n');
    }
    Ok(contents)
}

/// Replace `<home>/.ssh/authorized_keys` with `contents`, owned by
/// `uid:gid`, mode `0600`, in a `0700` `.ssh` directory.
///
/// `home` itself is resolved normally (it comes from the account database
/// and may be under a symlink such as bootc's `/home -> /var/home`); `.ssh`
/// and the file are not followed if they are symlinks.
fn write_authorized_keys(home: &Path, uid: Uid, gid: Gid, contents: &[u8]) -> Result<PathBuf> {
    let directory = OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_CLOEXEC;
    let home_fd = openat(AT_FDCWD, home, directory, Mode::empty())
        .with_context(|| format!("failed to open `{}`", home.display()))?;
    match mkdirat(&home_fd, ".ssh", Mode::from_bits_truncate(0o700)) {
        Ok(()) | Err(Errno::EEXIST) => {}
        Err(error) => return Err(error).context("failed to create `.ssh`"),
    }
    let ssh_fd = openat(&home_fd, ".ssh", directory | OFlag::O_NOFOLLOW, Mode::empty())
        .with_context(|| format!("`{}/.ssh` is not a directory", home.display()))?;
    fchown(&ssh_fd, Some(uid), Some(gid)).context("failed to chown `.ssh`")?;
    fchmod(&ssh_fd, Mode::from_bits_truncate(0o700)).context("failed to chmod `.ssh`")?;

    let temporary = format!(
        ".{AUTHORIZED_KEYS}.tetra-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    );
    let result = write_new_file(&ssh_fd, &temporary, uid, gid, contents)
        .and_then(|()| {
            renameat(&ssh_fd, temporary.as_str(), &ssh_fd, AUTHORIZED_KEYS)
                .context("failed to install `authorized_keys`")
        })
        .and_then(|()| fsync(&ssh_fd).context("failed to sync `.ssh`"));
    if result.is_err() {
        unlinkat(&ssh_fd, temporary.as_str(), UnlinkatFlags::NoRemoveDir).ok();
    }
    result.map(|()| home.join(".ssh").join(AUTHORIZED_KEYS))
}

fn write_new_file(dir: &OwnedFd, name: &str, uid: Uid, gid: Gid, contents: &[u8]) -> Result<()> {
    let fd = openat(
        dir.as_fd(),
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .context("failed to create the new `authorized_keys`")?;
    fchown(&fd, Some(uid), Some(gid)).context("failed to chown `authorized_keys`")?;
    // The umask may have narrowed the mode; set it explicitly.
    fchmod(&fd, Mode::from_bits_truncate(0o600)).context("failed to chmod `authorized_keys`")?;
    let mut file = fs::File::from(fd);
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

/// Small helper to read a host file with a context-bearing error. Used for
/// `/etc/passwd` and `/etc/group`.
fn read_file(path: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read `{path}`"))
}

/// Parses `/etc/passwd` into user objects.
///
/// The passwd format is `name:passwd:uid:gid:gecos:home:shell` (7 fields). We
/// intentionally skip field 1 (`passwd`), which is `x` under shadow passwords
/// and never useful to the control plane. The `>= 7` guard drops malformed or
/// comment lines rather than panicking.
fn parse_passwd(contents: &str) -> Vec<Value> {
    contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() >= 7).then(|| {
                jsonf! {
                    "name": fields[0],
                    "uid": fields[2],
                    "gid": fields[3],
                    "gecos": fields[4],
                    "home": fields[5],
                    "shell": fields[6],
                }
            })
        })
        .collect()
}

/// Parses `/etc/group` into group objects.
///
/// The group format is `name:passwd:gid:members` (4 fields), where `members`
/// is a comma-separated list. The `passwd` field (index 1) is skipped. Empty
/// member strings are filtered out so a trailing comma does not yield a bogus
/// empty member.
fn parse_group(contents: &str) -> Vec<Value> {
    contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() >= 4).then(|| {
                jsonf! {
                    "name": fields[0],
                    "gid": fields[2],
                    "members": fields[3].split(',').filter(|member| !member.is_empty()).collect::<Vec<_>>(),
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_passwd_entries() {
        let users = parse_passwd("root:x:0:0:root:/root:/bin/bash\n");
        assert_eq!(users[0]["name"], "root");
        assert_eq!(users[0]["home"], "/root");
    }

    #[test]
    fn parses_group_entries() {
        let groups = parse_group("wheel:x:10:root,admin\n");
        assert_eq!(groups[0]["name"], "wheel");
        assert_eq!(groups[0]["members"][0], "root");
    }

    #[test]
    fn dry_run_create_does_not_call_useradd() {
        let response = Create {
            name: "testuser".into(),
            shell: None,
            home: None,
            system: false,
            dry_run: true,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["command"], "useradd testuser");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }

    #[test]
    fn add_admin_appends_the_admin_group() {
        let response = AddAdmin {
            name: "alice".into(),
            dry_run: true,
        }
        .handle(None)
        .unwrap();
        assert_eq!(
            response["command"],
            "usermod --append --groups ultramarine-admin alice"
        );
        assert!(INFO.is_privileged("add_admin"));
    }

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq1 alice@laptop";

    #[test]
    fn authorized_keys_are_validated_one_per_line() {
        assert_eq!(
            authorized_keys(&[KEY.into(), format!("  {KEY}  ")]).unwrap(),
            format!("{KEY}\n{KEY}\n")
        );
        assert_eq!(authorized_keys(&[]).unwrap(), "");
        authorized_keys(&[
            r#"from="10.0.0.0/8",no-pty sk-ssh-ed25519@openssh.com AAAA key"#.into(),
        ])
        .unwrap();
        for bad in [
            format!("{KEY}\nssh-rsa AAAA injected"),
            "not a key".to_owned(),
            String::new(),
            format!("{KEY}\0"),
        ] {
            authorized_keys(&[bad]).unwrap_err();
        }
        authorized_keys(&vec![KEY.to_owned(); MAX_KEYS + 1]).unwrap_err();
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn writes_authorized_keys_private_and_owned_by_the_user() {
        let home = tempfile::tempdir().unwrap();
        let (uid, gid) = (Uid::current(), Gid::current());
        let path = write_authorized_keys(home.path(), uid, gid, b"one\n").unwrap();
        assert_eq!(path, home.path().join(".ssh/authorized_keys"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&home.path().join(".ssh")), 0o700);

        // Replacing keeps the directory and leaves no temporary files.
        fs::set_permissions(
            home.path().join(".ssh"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        write_authorized_keys(home.path(), uid, gid, b"two\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        assert_eq!(mode(&home.path().join(".ssh")), 0o700);
        assert_eq!(fs::read_dir(home.path().join(".ssh")).unwrap().count(), 1);
    }

    #[test]
    fn symlinks_in_the_home_directory_are_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let (uid, gid) = (Uid::current(), Gid::current());

        // `.ssh` pointing elsewhere: refused.
        std::os::unix::fs::symlink(outside.path(), home.path().join(".ssh")).unwrap();
        write_authorized_keys(home.path(), uid, gid, b"key\n").unwrap_err();
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
        fs::remove_file(home.path().join(".ssh")).unwrap();

        // `authorized_keys` pointing elsewhere: the link is replaced.
        let target = outside.path().join("victim");
        fs::write(&target, "untouched").unwrap();
        fs::create_dir_all(home.path().join(".ssh")).unwrap();
        std::os::unix::fs::symlink(&target, home.path().join(".ssh/authorized_keys")).unwrap();
        let path = write_authorized_keys(home.path(), uid, gid, b"key\n").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert!(!fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_to_string(&path).unwrap(), "key\n");
    }

    #[test]
    fn set_authorized_keys_dry_run_does_not_write() {
        let name = nix::unistd::User::from_uid(Uid::current())
            .unwrap()
            .unwrap()
            .name;
        let response = SetAuthorizedKeys {
            name,
            keys: vec![KEY.into()],
            dry_run: true,
        }
        .handle(None)
        .unwrap();
        assert_eq!(response["written"], false);
        assert_eq!(response["keys"], 1);
        assert!(
            response["path"]
                .as_str()
                .unwrap()
                .ends_with("/.ssh/authorized_keys")
        );
        SetAuthorizedKeys {
            name: "no-such-user-tetra-test".into(),
            keys: vec![],
            dry_run: true,
        }
        .handle(None)
        .unwrap_err();
    }
}
