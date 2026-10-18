//! Who may log in, and who is an administrator.
//!
//! Identity is the host's system accounts. An account may log in to the
//! dashboard when:
//!
//! - its UID is at least `UID_MIN` from `/etc/login.defs` (default 1000),
//! - its shell is listed in `/etc/shells` and is not a `nologin`/`false` shell,
//! - its shadow entry is not locked (`!`/`*`) and has not expired, and
//! - it is not on the exclusion list (`ultramarine-apps` by default).
//!
//! This is checked on every login, including passkey logins, and again on
//! every request a session makes. Administrators are members of
//! `ultramarine-admin` or `wheel`, resolved fresh for every privileged action.

use nix::unistd::{Gid, Group, User, getgrouplist};
use std::ffi::CString;

use crate::prelude::*;

/// Groups whose members are administrators.
pub const ADMIN_GROUPS: &[&str] = &["ultramarine-admin", "wheel"];
/// Accounts that never log in to the dashboard, whatever their shell.
pub const DEFAULT_EXCLUDED: &[&str] = &["ultramarine-apps"];
const DEFAULT_UID_MIN: u32 = 1000;
const SECONDS_PER_DAY: i64 = 86_400;

/// Password-state facts from `/etc/shadow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowState {
    Active,
    Locked,
    Expired,
    /// No shadow entry (for example an account from another NSS source).
    /// PAM's account stack still applies.
    Missing,
}

/// A host account as seen by Tetra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub shell: String,
    /// Names of every group the account belongs to, primary group included.
    pub groups: Vec<String>,
    pub shadow: ShadowState,
}

impl Account {
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.groups
            .iter()
            .any(|group| ADMIN_GROUPS.contains(&group.as_str()))
    }
}

/// Source of host accounts. [`SystemAccounts`] in production.
pub trait AccountSource: Send + Sync {
    /// # Errors
    /// Fails when the account database cannot be read.
    fn by_name(&self, name: &str) -> Result<Option<Account>>;
    /// # Errors
    /// Fails when the account database cannot be read.
    fn by_uid(&self, uid: u32) -> Result<Option<Account>>;
    /// Every local account name, used to look for an eligible administrator
    /// before setup completes.
    ///
    /// # Errors
    /// Fails when the account database cannot be read.
    fn names(&self) -> Result<Vec<String>>;
}

/// Accounts from NSS, with shadow state read from `/etc/shadow`.
#[derive(Debug, Clone)]
pub struct SystemAccounts {
    pub passwd: PathBuf,
    pub shadow: PathBuf,
}

impl Default for SystemAccounts {
    fn default() -> Self {
        Self {
            passwd: "/etc/passwd".into(),
            shadow: "/etc/shadow".into(),
        }
    }
}

impl SystemAccounts {
    fn account(&self, user: User) -> Result<Account> {
        let name = CString::new(user.name.as_str())?;
        let groups = getgrouplist(&name, user.gid)
            .with_context(|| format!("failed to list groups of `{}`", user.name))?
            .into_iter()
            .filter_map(|gid: Gid| Group::from_gid(gid).ok().flatten().map(|group| group.name))
            .collect();
        let shadow = match fs::read_to_string(&self.shadow) {
            Ok(text) => shadow_state(&text, &user.name, today()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => ShadowState::Missing,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read `{}`", self.shadow.display()));
            }
        };
        Ok(Account {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            shell: user.shell.to_string_lossy().into_owned(),
            name: user.name,
            groups,
            shadow,
        })
    }
}

impl AccountSource for SystemAccounts {
    fn by_name(&self, name: &str) -> Result<Option<Account>> {
        if name.is_empty() || name.contains('\0') {
            return Ok(None);
        }
        User::from_name(name)?
            .map(|user| self.account(user))
            .transpose()
    }

    fn by_uid(&self, uid: u32) -> Result<Option<Account>> {
        User::from_uid(uid.into())?
            .map(|user| self.account(user))
            .transpose()
    }

    fn names(&self) -> Result<Vec<String>> {
        let text = fs::read_to_string(&self.passwd)
            .with_context(|| format!("failed to read `{}`", self.passwd.display()))?;
        Ok(text
            .lines()
            .filter_map(|line| line.split(':').next())
            .filter(|name| !name.is_empty() && !name.starts_with('#'))
            .map(str::to_owned)
            .collect())
    }
}

/// Why an account may not log in. Logged, never shown to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligible {
    SystemAccount,
    NoLoginShell,
    Locked,
    Expired,
    Excluded,
}

impl std::fmt::Display for Ineligible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SystemAccount => "UID is below UID_MIN",
            Self::NoLoginShell => "account has no login shell",
            Self::Locked => "account is locked",
            Self::Expired => "account has expired",
            Self::Excluded => "account is excluded from dashboard login",
        })
    }
}

/// The login rules, loaded from `/etc/login.defs` and `/etc/shells`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPolicy {
    pub uid_min: u32,
    pub shells: Vec<String>,
    pub excluded: Vec<String>,
}

impl LoginPolicy {
    /// Read `UID_MIN` and the valid shells. Missing files fall back to
    /// `UID_MIN=1000` and no valid shells (so nobody can log in rather than
    /// everybody).
    ///
    /// # Errors
    /// Fails when a file exists but cannot be read.
    pub fn load(login_defs: &Path, shells: &Path, excluded: Vec<String>) -> Result<Self> {
        let read = |path: &Path| match fs::read_to_string(path) {
            Ok(text) => Ok(text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => {
                Err(error).with_context(|| format!("failed to read `{}`", path.display()))
            }
        };
        Ok(Self {
            uid_min: uid_min(&read(login_defs)?),
            shells: read(shells)?
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_owned)
                .collect(),
            excluded,
        })
    }

    /// Check whether `account` may log in.
    ///
    /// # Errors
    /// Returns the first rule the account fails.
    pub fn check(&self, account: &Account) -> Result<(), Ineligible> {
        if self.excluded.iter().any(|name| name == &account.name) {
            return Err(Ineligible::Excluded);
        }
        if account.uid < self.uid_min {
            return Err(Ineligible::SystemAccount);
        }
        let shell = account.shell.as_str();
        let no_login = shell.ends_with("/nologin") || shell.ends_with("/false");
        if no_login || !self.shells.iter().any(|valid| valid == shell) {
            return Err(Ineligible::NoLoginShell);
        }
        match account.shadow {
            ShadowState::Locked => Err(Ineligible::Locked),
            ShadowState::Expired => Err(Ineligible::Expired),
            ShadowState::Active | ShadowState::Missing => Ok(()),
        }
    }
}

fn uid_min(login_defs: &str) -> u32 {
    login_defs
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("UID_MIN")).then(|| fields.next()?.parse().ok())?
        })
        .next_back()
        .unwrap_or(DEFAULT_UID_MIN)
}

/// Days since the epoch, the unit `/etc/shadow` uses.
fn today() -> i64 {
    crate::agent::protocol::unix_timestamp() / SECONDS_PER_DAY
}

/// Interpret `name`'s line in shadow(5) text.
fn shadow_state(shadow: &str, name: &str, today: i64) -> ShadowState {
    let Some(fields) = shadow
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.first() == Some(&name))
    else {
        return ShadowState::Missing;
    };
    let password = fields.get(1).copied().unwrap_or_default();
    if password.starts_with('!') || password.starts_with('*') {
        return ShadowState::Locked;
    }
    let expire = fields.get(7).and_then(|days| days.parse::<i64>().ok());
    if expire.is_some_and(|days| today >= days) {
        return ShadowState::Expired;
    }
    ShadowState::Active
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LoginPolicy {
        LoginPolicy {
            uid_min: 1000,
            shells: vec!["/bin/bash".into(), "/usr/bin/zsh".into()],
            excluded: vec!["ultramarine-apps".into()],
        }
    }

    fn account(name: &str, uid: u32, shell: &str, shadow: ShadowState) -> Account {
        Account {
            uid,
            gid: uid,
            name: name.into(),
            shell: shell.into(),
            groups: vec![name.into()],
            shadow,
        }
    }

    #[test]
    fn regular_accounts_may_log_in() {
        let alice = account("alice", 1000, "/bin/bash", ShadowState::Active);
        policy().check(&alice).unwrap();
    }

    #[test]
    fn rejects_system_nologin_locked_expired_and_excluded_accounts() {
        let policy = policy();
        let cases = [
            (
                account("daemon", 2, "/bin/bash", ShadowState::Active),
                Ineligible::SystemAccount,
            ),
            (
                account("svc", 1001, "/sbin/nologin", ShadowState::Active),
                Ineligible::NoLoginShell,
            ),
            (
                account("odd", 1001, "/bin/ksh", ShadowState::Active),
                Ineligible::NoLoginShell,
            ),
            (
                account("bob", 1002, "/bin/bash", ShadowState::Locked),
                Ineligible::Locked,
            ),
            (
                account("eve", 1003, "/bin/bash", ShadowState::Expired),
                Ineligible::Expired,
            ),
            (
                account("ultramarine-apps", 1004, "/bin/bash", ShadowState::Active),
                Ineligible::Excluded,
            ),
        ];
        for (account, reason) in cases {
            assert_eq!(policy.check(&account), Err(reason), "{}", account.name);
        }
    }

    #[test]
    fn admins_are_members_of_ultramarine_admin_or_wheel() {
        let mut alice = account("alice", 1000, "/bin/bash", ShadowState::Active);
        assert!(!alice.is_admin());
        alice.groups.push("wheel".into());
        assert!(alice.is_admin());
        alice.groups = vec!["ultramarine-admin".into()];
        assert!(alice.is_admin());
    }

    #[test]
    fn reads_uid_min_and_shells() {
        let dir = tempfile::tempdir().unwrap();
        let defs = dir.path().join("login.defs");
        let shells = dir.path().join("shells");
        fs::write(&defs, "# comment\nUID_MIN   1500\nUID_MAX 60000\n").unwrap();
        fs::write(&shells, "/bin/sh\n# comment\n/bin/bash\n").unwrap();
        let policy = LoginPolicy::load(&defs, &shells, vec![]).unwrap();
        assert_eq!(policy.uid_min, 1500);
        assert_eq!(policy.shells, ["/bin/sh", "/bin/bash"]);

        let missing = LoginPolicy::load(&dir.path().join("x"), &dir.path().join("y"), vec![]);
        assert_eq!(missing.unwrap().uid_min, DEFAULT_UID_MIN);
    }

    #[test]
    fn interprets_shadow_entries() {
        let shadow = "alice:$y$hash:19000:0:99999:7:::\n\
                      bob:!$y$hash:19000:0:99999:7:::\n\
                      new:!!:19000::::::\n\
                      gone:$y$hash:19000:0:99999:7::19500:\n";
        assert_eq!(shadow_state(shadow, "alice", 20000), ShadowState::Active);
        assert_eq!(shadow_state(shadow, "bob", 20000), ShadowState::Locked);
        assert_eq!(shadow_state(shadow, "new", 20000), ShadowState::Locked);
        assert_eq!(shadow_state(shadow, "gone", 19499), ShadowState::Active);
        assert_eq!(shadow_state(shadow, "gone", 19500), ShadowState::Expired);
        assert_eq!(shadow_state(shadow, "nobody", 20000), ShadowState::Missing);
    }
}
