//! Passkey (WebAuthn) ceremony state.
//!
//! The browser runs the WebAuthn ceremony and the dashboard relays JSON both
//! ways; Tetra creates every challenge, keeps the matching state in memory
//! (never on disk, never in the dashboard) and verifies the result. Ceremony
//! state is single-use and expires after [`CEREMONY_TTL`] seconds.
//!
//! Login is username-first, the flow webauthn-rs recommends: with a username
//! Tetra asks for that user's registered credentials. Without one (or for a
//! username that has no passkeys, so the answer does not reveal that) it
//! issues a discoverable-credential challenge and identifies the user from the
//! credential's user handle.

use std::{collections::HashMap, sync::Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration,
};

use super::sessions::ClientKind;

/// Seconds a ceremony may take.
pub const CEREMONY_TTL: i64 = 300;
/// Upper bound on concurrent ceremonies, so unauthenticated callers cannot
/// grow Tetra's memory without limit.
pub const MAX_PENDING: usize = 256;

/// Base64url form of a credential ID, as stored and shown.
#[must_use]
pub fn credential_id(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())
}

/// A pending registration for a logged-in user.
pub struct Registration {
    pub client: ClientKind,
    pub uid: u32,
    pub username: String,
    pub name: String,
    pub state: PasskeyRegistration,
    pub expires_at: i64,
}

/// A pending login.
pub struct Authentication {
    pub client: ClientKind,
    pub state: AuthenticationState,
    pub expires_at: i64,
}

pub enum AuthenticationState {
    /// Username-first: the user is known from the start.
    Known {
        uid: u32,
        username: String,
        state: PasskeyAuthentication,
    },
    /// Discoverable: the user comes from the credential's user handle.
    Discoverable(DiscoverableAuthentication),
}

/// Expiring, single-use, bounded in-memory state keyed by a random ID.
pub struct Pending<T> {
    entries: Mutex<HashMap<String, (i64, T)>>,
}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> Pending<T> {
    /// Store `value` until `expires_at`, returning its ID, or `None` when
    /// too many entries are pending.
    pub fn insert(&self, value: T, expires_at: i64, now: i64) -> Option<String> {
        let mut bytes = [0_u8; 24];
        rand::fill(&mut bytes);
        let id = URL_SAFE_NO_PAD.encode(bytes);
        let mut entries = self.lock();
        entries.retain(|_, (expiry, _)| *expiry > now);
        if entries.len() >= MAX_PENDING {
            return None;
        }
        entries.insert(id.clone(), (expires_at, value));
        drop(entries);
        Some(id)
    }

    /// Remove and return the live entry for `id`.
    pub fn take(&self, id: &str, now: i64) -> Option<T> {
        let (expires_at, value) = self.lock().remove(id)?;
        (expires_at > now).then_some(value)
    }

    /// Put an entry back (for example after a failed attempt that may be
    /// retried).
    pub fn restore(&self, id: String, value: T, expires_at: i64) {
        self.lock().insert(id, (expires_at, value));
    }

    /// Drop every entry matching `select`.
    pub fn remove_where<F: Fn(&T) -> bool>(&self, select: F) {
        self.lock().retain(|_, (_, value)| !select(value));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (i64, T)>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_entries_are_single_use_and_expire() {
        let pending = Pending::default();
        let id = pending.insert("a", 100, 0).unwrap();
        assert_eq!(pending.take(&id, 50), Some("a"));
        assert_eq!(pending.take(&id, 50), None);

        let id = pending.insert("b", 100, 0).unwrap();
        assert_eq!(pending.take(&id, 100), None);
    }

    #[test]
    fn pending_entries_are_bounded() {
        let pending = Pending::default();
        for _ in 0..MAX_PENDING {
            pending.insert((), 100, 0).unwrap();
        }
        assert!(pending.insert((), 100, 0).is_none());
        // Expired entries make room again.
        assert!(pending.insert((), 200, 100).is_some());
    }
}
