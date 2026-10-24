//! Passkey (WebAuthn) ceremony state.
//!
//! The browser runs the WebAuthn ceremony and the dashboard relays JSON both
//! ways; Tetra creates every challenge, keeps the matching state in memory
//! (never on disk, never in the dashboard) and verifies the result. Ceremony
//! state is single-use and expires after [`CEREMONY_TTL`] seconds.
//!
//! Passkeys are registered as discoverable credentials where the
//! authenticator can store one (`residentKey: "preferred"`), so the primary
//! login is usernameless: without a username Tetra issues a
//! discoverable-credential challenge, usable with autofill (conditional
//! mediation), and identifies the user from the credential's user handle.
//!
//! Username-first login is the fallback for keys that could not store a
//! discoverable credential: with a username Tetra asks for that user's
//! registered credentials. For a username that does not exist, may not log in
//! or has no passkeys, it lists a decoy credential derived from the username
//! with the store key instead, which stays the same across requests and
//! restarts. The decoy looks like a single platform passkey, so it hides users
//! that have one; a user with several passkeys or security keys can still be
//! told apart by the list's length and transports. (The real credential IDs
//! of a user with passkeys are visible to anyone who knows the username;
//! WebAuthn does not treat them as secret.)
//!
//! Pending ceremonies are limited per owner (the browser's address for
//! logins, the user for registrations): a new one replaces the owner's oldest
//! once [`MAX_PER_OWNER`] are pending, so one source cannot fill the shared
//! [`MAX_PENDING`] limit and block everyone else. Logins without a usable
//! address only count against [`MAX_PENDING`].

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration,
};

use super::sessions::ClientKind;

/// Seconds a ceremony may take.
pub const CEREMONY_TTL: i64 = 300;
/// Upper bound on concurrent ceremonies, so unauthenticated callers cannot
/// grow Tetra's memory without limit.
pub const MAX_PENDING: usize = 4096;
/// Pending entries per owner; more replace the owner's oldest.
pub const MAX_PER_OWNER: usize = 16;

/// [`super::seal::StoreKey::keyed_hash`] purpose for decoy credentials.
pub const DECOY_PURPOSE: &str = "passkey-decoy";

/// A credential descriptor (as in `allowCredentials`) for a credential that
/// does not exist, derived from `seed`. Shaped like a platform passkey's.
#[must_use]
pub fn decoy_credential(seed: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "type": "public-key",
        "id": URL_SAFE_NO_PAD.encode(seed),
        "transports": ["internal", "hybrid"],
    })
}

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
}

/// A pending login.
pub struct Authentication {
    pub client: ClientKind,
    pub state: AuthenticationState,
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
    entries: Mutex<HashMap<String, Entry<T>>>,
}

struct Entry<T> {
    owner: Option<String>,
    created: u64,
    expires_at: i64,
    value: T,
}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> Pending<T> {
    /// Store `value` for `owner` until `expires_at`, returning its ID, or
    /// `None` when [`MAX_PENDING`] entries are pending. An owner that already
    /// has [`MAX_PER_OWNER`] entries loses its oldest instead; entries without
    /// an owner only count against [`MAX_PENDING`].
    pub fn insert(
        &self,
        owner: Option<&str>,
        value: T,
        expires_at: i64,
        now: i64,
    ) -> Option<String> {
        let mut bytes = [0_u8; 24];
        rand::fill(&mut bytes);
        let id = URL_SAFE_NO_PAD.encode(bytes);
        self.put(id.clone(), owner, value, expires_at, now)
            .then_some(id)
    }

    /// Remove and return the live entry for `id`.
    pub fn take(&self, id: &str, now: i64) -> Option<T> {
        let entry = self.lock().remove(id)?;
        (entry.expires_at > now).then_some(entry.value)
    }

    /// Put an entry back (for example after a failed attempt that may be
    /// retried), under the same limits as [`Self::insert`].
    pub fn restore(&self, id: String, owner: Option<&str>, value: T, expires_at: i64, now: i64) {
        self.put(id, owner, value, expires_at, now);
    }

    fn put(&self, id: String, owner: Option<&str>, value: T, expires_at: i64, now: i64) -> bool {
        let mut entries = self.lock();
        entries.retain(|_, entry| entry.expires_at > now);
        if let Some(owner) = owner {
            let mut mine: Vec<_> = entries
                .iter()
                .filter(|(_, entry)| entry.owner.as_deref() == Some(owner))
                .map(|(id, entry)| (entry.created, id.clone()))
                .collect();
            if mine.len() >= MAX_PER_OWNER {
                mine.sort_unstable();
                let excess = mine.len().saturating_sub(MAX_PER_OWNER - 1);
                for (_, oldest) in mine.into_iter().take(excess) {
                    entries.remove(&oldest);
                }
            }
        }
        if entries.len() >= MAX_PENDING {
            return false;
        }
        entries.insert(
            id,
            Entry {
                owner: owner.map(str::to_owned),
                created: next_sequence(),
                expires_at,
                value,
            },
        );
        true
    }

    /// Drop every entry matching `select`.
    pub fn remove_where<F: Fn(&T) -> bool>(&self, select: F) {
        self.lock().retain(|_, entry| !select(&entry.value));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry<T>>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Insertion order, for replacing an owner's oldest entry.
fn next_sequence() -> u64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

/// The browser's IP address from `remote_addr`, without the port.
///
/// Accepts `ip`, `[ipv6]`, `ip:port` or `[ipv6]:port`; `None` for anything
/// else, so text a client made up never reaches PAM (`PAM_RHOST`).
#[must_use]
pub fn client_ip(remote_addr: Option<&str>) -> Option<IpAddr> {
    let remote_addr = remote_addr?.trim();
    let unbracketed = remote_addr
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(remote_addr);
    let ip = unbracketed
        .parse::<IpAddr>()
        .or_else(|_| remote_addr.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()?;
    Some(ip.to_canonical())
}

/// The owner of a login ceremony (and the setup-code throttle's key): the
/// browser's IP address, given as `ip`, `[ipv6]`, `ip:port` or `[ipv6]:port`.
///
/// IPv6 is grouped by `/64`, what one host typically controls. `None` when
/// the dashboard sent no address or one that is not an IP address, so a
/// caller cannot mint owners from arbitrary strings.
#[must_use]
pub fn source_owner(remote_addr: Option<&str>) -> Option<String> {
    Some(match client_ip(remote_addr)? {
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
        }
        ip @ IpAddr::V4(_) => ip.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_entries_are_single_use_and_expire() {
        let pending = Pending::default();
        let id = pending.insert(Some("o"), "a", 100, 0).unwrap();
        assert_eq!(pending.take(&id, 50), Some("a"));
        assert_eq!(pending.take(&id, 50), None);

        let id = pending.insert(None, "b", 100, 0).unwrap();
        assert_eq!(pending.take(&id, 100), None);
    }

    #[test]
    fn pending_entries_are_bounded() {
        let pending = Pending::default();
        for _ in 0..MAX_PENDING {
            pending.insert(None, (), 100, 0).unwrap();
        }
        assert!(pending.insert(Some("new"), (), 100, 0).is_none());
        // Restoring does not exceed the limit either.
        pending.restore("restored".into(), Some("new"), (), 100, 0);
        assert!(pending.take("restored", 0).is_none());
        // Expired entries make room again.
        assert!(pending.insert(Some("new"), (), 200, 100).is_some());
    }

    #[test]
    fn one_owner_replaces_its_own_oldest_entries() {
        let pending = Pending::default();
        let other = pending.insert(Some("other"), 0, 100, 0).unwrap();
        let first = pending.insert(Some("flood"), 1, 100, 0).unwrap();
        for value in 0..MAX_PENDING {
            pending.insert(Some("flood"), value, 100, 0).unwrap();
        }
        assert_eq!(pending.take(&first, 1), None);
        assert_eq!(pending.take(&other, 1), Some(0));
        assert_eq!(pending.lock().len(), MAX_PER_OWNER);
    }

    #[test]
    fn login_sources_group_ipv6_by_prefix() {
        let owner = |addr| source_owner(Some(addr));
        assert_eq!(owner("192.0.2.1"), owner("192.0.2.1:443"));
        assert_ne!(owner("192.0.2.1"), owner("192.0.2.2"));
        assert_eq!(owner("2001:db8:1:2::1"), owner("2001:db8:1:2:ffff::9"));
        assert_ne!(owner("2001:db8:1:2::1"), owner("2001:db8:1:3::1"));
        assert_eq!(owner("::ffff:192.0.2.1"), owner("192.0.2.1"));
        // Any source port, with or without brackets, is the same source.
        assert_eq!(owner("198.51.100.7:51234").as_deref(), Some("198.51.100.7"));
        assert_eq!(owner("198.51.100.7:51235"), owner("198.51.100.7"));
        assert_eq!(
            owner("[2001:db8:1:2::7]:51234").as_deref(),
            Some("2001:db8:1:2::/64")
        );
        assert_eq!(owner("[2001:db8:1:2::8]"), owner("[2001:db8:1:2::7]:1"));
        // Not an address: no owner, rather than one per distinct string.
        assert_eq!(owner("x, 192.0.2.1"), None);
        assert_eq!(source_owner(None), None);
    }
}
