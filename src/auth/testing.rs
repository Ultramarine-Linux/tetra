//! Test doubles for the host-facing parts of [`super`].
//!
//! Fakes for PAM, the account database, `systemd-creds` and the clock. They
//! are public so integration tests can build an
//! [`AuthService`](super::AuthService) without root, PAM or a TPM. Production
//! code never selects them. Like test code, they panic on poisoned locks.
#![allow(clippy::missing_panics_doc, clippy::unwrap_in_result)]

use std::sync::atomic::{AtomicI64, Ordering};

use crate::prelude::*;

use super::{clock::Clock, seal::Sealer};

/// [`Sealer`] that only tags the blob with its name. Not encryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeSealer;

impl Sealer for FakeSealer {
    fn seal(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok([format!("fake:{name}:").as_bytes(), plaintext].concat())
    }

    fn unseal(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        sealed
            .strip_prefix(format!("fake:{name}:").as_bytes())
            .map(<[u8]>::to_vec)
            .context("blob was not sealed under this name")
    }
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    #[must_use]
    pub const fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    pub fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// [`PasswordBackend`](super::pam::PasswordBackend) with a fixed password per
/// user. Records every call so tests can assert that the account stack ran.
#[derive(Debug, Default)]
pub struct MockPasswords {
    passwords: std::sync::Mutex<BTreeMap<String, String>>,
    expired: std::sync::Mutex<HashSet<String>>,
    denied_accounts: std::sync::Mutex<HashSet<String>>,
    locked_out: std::sync::Mutex<HashSet<String>>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl MockPasswords {
    pub fn set(&self, username: &str, password: &str) {
        self.passwords
            .lock()
            .unwrap()
            .insert(username.into(), password.into());
    }

    /// Make the password correct but expired.
    pub fn expire(&self, username: &str) {
        self.expired.lock().unwrap().insert(username.into());
    }

    /// Make the account stack deny `username`.
    pub fn deny_account(&self, username: &str) {
        self.denied_accounts.lock().unwrap().insert(username.into());
    }

    /// Lock `username` out like `pam_faillock` does: the auth stack denies
    /// even the right password; the account stack (which has no
    /// `pam_faillock`) is unaffected.
    pub fn lock_out(&self, username: &str) {
        self.locked_out.lock().unwrap().insert(username.into());
    }

    /// Calls so far, as `auth:<user>` or `account:<user>`.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl super::pam::PasswordBackend for MockPasswords {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
        _rhost: Option<&str>,
    ) -> super::pam::PamOutcome {
        use super::pam::PamOutcome;
        self.calls.lock().unwrap().push(format!("auth:{username}"));
        if self.locked_out.lock().unwrap().contains(username) {
            return PamOutcome::Denied;
        }
        let correct = self.passwords.lock().unwrap().get(username).cloned();
        if correct.as_deref() != Some(password) || password.is_empty() {
            return PamOutcome::Denied;
        }
        if self.expired.lock().unwrap().contains(username) {
            return PamOutcome::PasswordExpired;
        }
        if self.denied_accounts.lock().unwrap().contains(username) {
            return PamOutcome::Denied;
        }
        PamOutcome::Success
    }

    fn check_account(&self, username: &str, _rhost: Option<&str>) -> super::pam::PamOutcome {
        use super::pam::PamOutcome;
        self.calls
            .lock()
            .unwrap()
            .push(format!("account:{username}"));
        if self.denied_accounts.lock().unwrap().contains(username) {
            PamOutcome::Denied
        } else {
            PamOutcome::Success
        }
    }
}

/// [`AccountSource`](super::accounts::AccountSource) over an in-memory list.
#[derive(Debug, Default)]
pub struct StaticAccounts(std::sync::Mutex<Vec<super::accounts::Account>>);

impl StaticAccounts {
    /// Add or replace a regular account with `/bin/bash` as its shell.
    pub fn add(&self, name: &str, uid: u32, groups: &[&str]) {
        self.put(super::accounts::Account {
            uid,
            gid: uid,
            name: name.into(),
            shell: "/bin/bash".into(),
            groups: std::iter::once(name)
                .chain(groups.iter().copied())
                .map(str::to_owned)
                .collect(),
            shadow: super::accounts::ShadowState::Active,
        });
    }

    /// Add or replace an account.
    pub fn put(&self, account: super::accounts::Account) {
        let mut accounts = self.0.lock().unwrap();
        accounts.retain(|existing| existing.uid != account.uid && existing.name != account.name);
        accounts.push(account);
    }

    /// Change an account in place.
    pub fn update<F: FnOnce(&mut super::accounts::Account)>(&self, name: &str, change: F) {
        let mut accounts = self.0.lock().unwrap();
        if let Some(account) = accounts.iter_mut().find(|account| account.name == name) {
            change(account);
        }
    }

    pub fn remove(&self, name: &str) {
        self.0
            .lock()
            .unwrap()
            .retain(|account| account.name != name);
    }
}

impl super::accounts::AccountSource for StaticAccounts {
    fn by_name(&self, name: &str) -> Result<Option<super::accounts::Account>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.name == name)
            .cloned())
    }

    fn by_uid(&self, uid: u32) -> Result<Option<super::accounts::Account>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.uid == uid)
            .cloned())
    }

    fn names(&self) -> Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.name.clone())
            .collect())
    }
}

/// An [`AuthService`](super::AuthService) over fakes, rooted at a scratch
/// directory. Must be created inside a Tokio runtime.
pub struct TestHost {
    pub service: super::AuthService,
    pub config: super::AuthConfig,
    pub accounts: std::sync::Arc<StaticAccounts>,
    pub passwords: std::sync::Arc<MockPasswords>,
    pub clock: std::sync::Arc<ManualClock>,
}

/// Start time of a [`TestHost`] clock.
pub const TEST_EPOCH: i64 = 1_800_000_000;

impl TestHost {
    /// # Errors
    /// Fails when the scratch directories cannot be created.
    pub fn new(root: &Path) -> Result<Self> {
        use std::sync::Arc;
        let config = super::AuthConfig {
            state_dir: root.join("var/lib/tetra"),
            run_dir: root.join("run/tetra"),
            issue_dir: root.join("run/issue.d"),
            caddy_sites_dir: root.join("etc/caddy/tetra-sites"),
            reload_caddy: false,
            dashboard_upstream: super::access::DEFAULT_DASHBOARD_UPSTREAM.to_owned(),
            session_policy: super::sessions::SessionPolicy::default(),
        };
        let accounts = Arc::new(StaticAccounts::default());
        let passwords = Arc::new(MockPasswords::default());
        let clock = Arc::new(ManualClock::new(TEST_EPOCH));
        let queue = crate::agent::queue::DispatchQueue::spawn(
            crate::agent::AgentBackend::spawn_default(),
            crate::agent::queue::DEFAULT_QUEUE_CAPACITY,
        );
        let service = super::AuthService::new(
            config.clone(),
            super::Backends {
                accounts: Arc::clone(&accounts) as _,
                passwords: Arc::clone(&passwords) as _,
                sealer: Arc::new(FakeSealer),
                clock: Arc::clone(&clock) as _,
                policy: super::accounts::LoginPolicy {
                    uid_min: 1000,
                    shells: vec!["/bin/bash".into()],
                    excluded: super::accounts::DEFAULT_EXCLUDED
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect(),
                },
            },
            queue,
        )?;
        Ok(Self {
            service,
            config,
            accounts,
            passwords,
            clock,
        })
    }

    /// Re-create the service over the same directories and fakes, as after a
    /// Tetra restart.
    ///
    /// # Errors
    /// Fails when stored state cannot be loaded.
    pub fn restart(&self) -> Result<super::AuthService> {
        use std::sync::Arc;
        super::AuthService::new(
            self.config.clone(),
            super::Backends {
                accounts: Arc::clone(&self.accounts) as _,
                passwords: Arc::clone(&self.passwords) as _,
                sealer: Arc::new(FakeSealer),
                clock: Arc::clone(&self.clock) as _,
                policy: super::accounts::LoginPolicy {
                    uid_min: 1000,
                    shells: vec!["/bin/bash".into()],
                    excluded: vec!["ultramarine-apps".into()],
                },
            },
            crate::agent::queue::DispatchQueue::spawn(
                crate::agent::AgentBackend::spawn_default(),
                crate::agent::queue::DEFAULT_QUEUE_CAPACITY,
            ),
        )
    }
}
