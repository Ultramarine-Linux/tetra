//! Per-user credential records, one file per UID under
//! `/var/lib/tetra/auth/users/<uid>.json`.
//!
//! A record also stores the username it was created for. If the account is
//! deleted and its UID reused, the names no longer match and the old record
//! is ignored (and replaced on the next write), so a new account never
//! inherits someone else's second factor or passkeys.

use std::ffi::OsStr;

use webauthn_rs::prelude::{Passkey, Uuid};

use crate::prelude::*;

use super::{
    seal::Sealed,
    store::{self, Cached, Extra, Header, Record, StoreLock},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    #[serde(flatten)]
    header: Header,
    pub uid: u32,
    pub username: String,
    /// Bumped to invalidate every existing session of this user.
    #[serde(default)]
    pub session_epoch: u64,
    /// Stable WebAuthn user handle, assigned on first passkey registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_codes: Vec<RecoveryCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<PasskeyRecord>,
    /// Consecutive wrong second-factor codes, across logins.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub second_factor_failures: u32,
    /// No second-factor code is checked before this time.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub second_factor_retry_at: i64,
    #[serde(flatten)]
    extra: Extra,
}

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

impl Record for UserRecord {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

impl UserRecord {
    #[must_use]
    pub fn new(uid: u32, username: &str) -> Self {
        Self {
            header: Header::default(),
            uid,
            username: username.to_owned(),
            session_epoch: 0,
            webauthn_id: None,
            totp: None,
            recovery_codes: Vec::new(),
            passkeys: Vec::new(),
            second_factor_failures: 0,
            second_factor_retry_at: 0,
            extra: Extra::new(),
        }
    }

    /// Unused recovery codes left.
    #[must_use]
    pub fn recovery_codes_left(&self) -> usize {
        self.recovery_codes
            .iter()
            .filter(|code| code.used_at.is_none())
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpRecord {
    /// The shared secret, encrypted with the store key.
    pub secret: Sealed,
    pub enrolled_at: i64,
    /// Last accepted time step; a code is never accepted twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_step: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    /// SHA-256 of the normalized code.
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    /// Base64url credential ID.
    pub id: String,
    pub name: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    /// Public key and signature counter. Not secret.
    pub passkey: Passkey,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `users/` directory.
#[derive(Debug, Clone)]
pub struct UserStore {
    dir: PathBuf,
    /// Records last read, by UID: every request of a user session checks
    /// its record's `session_epoch`.
    cache: Cached<Option<UserRecord>, u32>,
}

impl UserStore {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            cache: Cached::new(),
        }
    }

    fn path(&self, uid: u32) -> PathBuf {
        self.dir.join(format!("{uid}.json"))
    }

    /// The record for `uid`, if one exists and was created for `username`.
    ///
    /// # Errors
    /// Fails when the record exists but cannot be read, or belongs to another
    /// name and holds a TOTP secret: that is a renamed account (`usermod -l`)
    /// as often as a reused UID, and ignoring its second factor would fail
    /// open. `tetra auth reset-2fa` clears it.
    pub fn get(&self, uid: u32, username: &str) -> Result<Option<UserRecord>> {
        let cached = self
            .cache
            .get(uid, &self.path(uid), || self.read_uid(uid))?;
        let Some(record) = cached.as_ref() else {
            return Ok(None);
        };
        if record.username == username {
            return Ok(Some(record.clone()));
        }
        ensure!(
            record.totp.is_none(),
            "the second factor for UID {uid} belongs to `{}`, not `{username}`; \
             run `tetra auth reset-2fa {username}`",
            record.username
        );
        Ok(None)
    }

    /// The stored record for `uid`, whoever it was created for.
    fn read_uid(&self, uid: u32) -> Result<Option<UserRecord>> {
        Ok(store::read::<UserRecord>(&self.path(uid))?.filter(|record| record.uid == uid))
    }

    /// Read-modify-write the record for `uid` under the store lock, starting
    /// from an empty record when there is none (or it belonged to a previous
    /// owner of the UID). The record is written only when `change` succeeds.
    ///
    /// # Errors
    /// Fails when `change` fails or the record cannot be read or written.
    pub fn update<R, F>(&self, uid: u32, username: &str, change: F) -> Result<R>
    where
        F: FnOnce(&mut UserRecord) -> Result<R>,
    {
        let _lock = StoreLock::acquire(&self.dir)?;
        // A previous owner's record is discarded here (not refused as in
        // `get`), so `reset-2fa` can recover a renamed account.
        let mut record = self
            .read_uid(uid)?
            .filter(|record| record.username == username)
            .unwrap_or_else(|| UserRecord::new(uid, username));
        let result = change(&mut record)?;
        let written = store::write(&self.path(uid), &mut record);
        self.cache.invalidate(&uid);
        written?;
        Ok(result)
    }

    /// Every stored record. Unreadable files are logged and skipped.
    ///
    /// # Errors
    /// Fails when the directory exists but cannot be listed.
    pub fn all(&self) -> Result<Vec<UserRecord>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to list `{}`", self.dir.display()));
            }
        };
        let mut records = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(OsStr::to_str) != Some("json") {
                continue;
            }
            match store::read::<UserRecord>(&path) {
                Ok(Some(record)) => records.push(record),
                Ok(None) => {}
                Err(error) => eprintln!("skipping user record: {error:#}"),
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_ignore_a_previous_owner_of_the_uid() {
        let dir = tempfile::tempdir().unwrap();
        let users = UserStore::new(dir.path().join("users"));
        assert!(users.get(1000, "alice").unwrap().is_none());
        users
            .update(1000, "alice", |record| {
                record.session_epoch = 3;
                Ok(())
            })
            .unwrap();
        assert_eq!(users.get(1000, "alice").unwrap().unwrap().session_epoch, 3);

        // alice was deleted and bob got her UID.
        assert!(users.get(1000, "bob").unwrap().is_none());
        let epoch = users
            .update(1000, "bob", |record| Ok(record.session_epoch))
            .unwrap();
        assert_eq!(epoch, 0);
        assert!(users.get(1000, "alice").unwrap().is_none());
    }

    #[test]
    fn a_renamed_account_does_not_lose_its_totp() {
        let dir = tempfile::tempdir().unwrap();
        let users = UserStore::new(dir.path().join("users"));
        users
            .update(1000, "alice", |record| {
                record.totp = Some(TotpRecord {
                    secret: Sealed::default(),
                    enrolled_at: 0,
                    last_step: None,
                    extra: Extra::new(),
                });
                Ok(())
            })
            .unwrap();
        // `usermod -l alice alice2`: refuse rather than skip the second factor.
        users.get(1000, "alice2").unwrap_err();
        // Resetting (an update under the new name) starts a fresh record.
        users.update(1000, "alice2", |_| Ok(())).unwrap();
        assert!(users.get(1000, "alice2").unwrap().unwrap().totp.is_none());
    }

    #[test]
    fn failed_updates_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let users = UserStore::new(dir.path().join("users"));
        users
            .update(1000, "alice", |record| -> Result<()> {
                record.session_epoch = 1;
                bail!("rejected")
            })
            .unwrap_err();
        assert!(users.get(1000, "alice").unwrap().is_none());
    }
}
