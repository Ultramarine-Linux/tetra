//! Session tokens.
//!
//! A token is issued only after full authentication (password plus TOTP when
//! enrolled, a passkey, or the setup code) and is bound to the local client
//! type it was issued to: a dashboard token is useless on the OOBE's
//! connection and vice versa. Only the SHA-256 hash of a token is kept.
//!
//! Sessions survive a Tetra restart through `/var/lib/tetra/auth/sessions.json`.
//! The file is rewritten when a session is issued or revoked; `last_seen`
//! changes stay in memory and are written by [`SessionStore::flush`], which
//! the daemon calls periodically, so requests never wait on disk.

use std::{collections::HashMap, sync::Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::prelude::*;

use super::store::{self, Extra, Header, Record};

/// Prefix that makes tokens easy to recognize in logs and secret scanners.
pub const TOKEN_PREFIX: &str = "tts_";
const TOKEN_BYTES: usize = 32;
const PUBLIC_ID_CHARS: usize = 16;

/// Which local client a connection (and so a token) belongs to, from the
/// peer's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Dashboard,
    Oobe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// A logged-in host account.
    User,
    /// The first-boot setup session, limited to OOBE operations.
    Setup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    PasswordTotp,
    PasswordRecoveryCode,
    Passkey,
    SetupCode,
}

/// Lifetimes, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Absolute lifetime of a user session.
    pub lifetime: i64,
    /// A session unused for this long expires.
    pub idle: i64,
    /// Absolute lifetime of a setup session.
    pub setup_lifetime: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            lifetime: 12 * 3600,
            idle: 3600,
            setup_lifetime: 2 * 3600,
        }
    }
}

/// A stored session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Public identifier, safe to show and to pass to `session.revoke`.
    pub id: String,
    token_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub client: ClientKind,
    pub kind: SessionKind,
    pub method: AuthMethod,
    /// The user's session epoch at issue time. Bumping the epoch (second
    /// factor reset, admin revoke) invalidates every older session.
    #[serde(default)]
    pub epoch: u64,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen: i64,
    #[serde(flatten)]
    extra: Extra,
}

/// What to issue a session for.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub uid: Option<u32>,
    pub username: Option<String>,
    pub client: ClientKind,
    pub kind: SessionKind,
    pub method: AuthMethod,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Unknown, revoked or malformed token.
    Invalid,
    Expired,
    /// The token belongs to the other local client.
    WrongClient,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SessionsFile {
    #[serde(flatten)]
    header: Header,
    #[serde(default)]
    sessions: Vec<Session>,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for SessionsFile {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

struct State {
    sessions: HashMap<String, Session>,
    extra: Extra,
    dirty: bool,
}

/// All live sessions.
pub struct SessionStore {
    path: PathBuf,
    policy: SessionPolicy,
    state: Mutex<State>,
}

/// Hash a token for lookup and storage.
#[must_use]
pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").ok();
        out
    })
}

impl SessionStore {
    /// Load sessions from `path`, dropping any that have expired.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn load(path: PathBuf, policy: SessionPolicy, now: i64) -> Result<Self> {
        let file = store::read::<SessionsFile>(&path)?.unwrap_or_default();
        let sessions = file
            .sessions
            .into_iter()
            .filter(|session| live(&policy, session, now))
            .map(|session| (session.token_hash.clone(), session))
            .collect();
        Ok(Self {
            path,
            policy,
            state: Mutex::new(State {
                sessions,
                extra: file.extra,
                dirty: false,
            }),
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// Issue a new session and return its token. The token is never stored.
    ///
    /// # Errors
    /// Fails when the session file cannot be written.
    pub fn issue(&self, new: NewSession, now: i64) -> Result<(String, Session)> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        rand::fill(&mut bytes);
        let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        let token_hash = hash_token(&token);
        let lifetime = match new.kind {
            SessionKind::User => self.policy.lifetime,
            SessionKind::Setup => self.policy.setup_lifetime,
        };
        let session = Session {
            id: token_hash.chars().take(PUBLIC_ID_CHARS).collect(),
            token_hash: token_hash.clone(),
            uid: new.uid,
            username: new.username,
            client: new.client,
            kind: new.kind,
            method: new.method,
            epoch: new.epoch,
            created_at: now,
            expires_at: now.saturating_add(lifetime),
            last_seen: now,
            extra: Extra::new(),
        };
        let mut state = self.lock();
        state.sessions.insert(token_hash, session.clone());
        let persisted = self.persist(&mut state);
        drop(state);
        persisted?;
        Ok((token, session))
    }

    /// Look up `token` for `client` and record the use.
    ///
    /// # Errors
    /// Returns why the token is not usable.
    pub fn validate(
        &self,
        token: &str,
        client: ClientKind,
        now: i64,
    ) -> Result<Session, SessionError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(SessionError::Invalid);
        }
        let hash = hash_token(token);
        let mut state = self.lock();
        let session = state.sessions.get(&hash).ok_or(SessionError::Invalid)?;
        if session.client != client {
            return Err(SessionError::WrongClient);
        }
        if !live(&self.policy, session, now) {
            state.sessions.remove(&hash);
            state.dirty = true;
            return Err(SessionError::Expired);
        }
        let session = state.sessions.get_mut(&hash).ok_or(SessionError::Invalid)?;
        session.last_seen = now;
        let session = session.clone();
        state.dirty = true;
        drop(state);
        Ok(session)
    }

    /// Revoke every session matching `select`, returning how many were
    /// revoked.
    ///
    /// # Errors
    /// Fails when the session file cannot be written.
    pub fn revoke<F: Fn(&Session) -> bool>(&self, select: F) -> Result<usize> {
        let mut state = self.lock();
        let before = state.sessions.len();
        state.sessions.retain(|_, session| !select(session));
        let revoked = before.saturating_sub(state.sessions.len());
        let persisted = if revoked > 0 {
            self.persist(&mut state)
        } else {
            Ok(())
        };
        drop(state);
        persisted.map(|()| revoked)
    }

    /// Live sessions matching `select`, oldest first.
    #[must_use]
    pub fn list<F: Fn(&Session) -> bool>(&self, select: F, now: i64) -> Vec<Session> {
        let mut sessions: Vec<_> = self
            .lock()
            .sessions
            .values()
            .filter(|session| live(&self.policy, session, now) && select(session))
            .cloned()
            .collect();
        sessions.sort_by_key(|session| session.created_at);
        sessions
    }

    /// Write pending `last_seen` updates and expiries, if any.
    ///
    /// # Errors
    /// Fails when the session file cannot be written.
    pub fn flush(&self) -> Result<()> {
        let mut state = self.lock();
        let persisted = if state.dirty {
            self.persist(&mut state)
        } else {
            Ok(())
        };
        drop(state);
        persisted
    }

    fn persist(&self, state: &mut State) -> Result<()> {
        let mut sessions: Vec<_> = state.sessions.values().cloned().collect();
        sessions.sort_by_key(|session| session.created_at);
        store::write(
            &self.path,
            &mut SessionsFile {
                header: Header::default(),
                sessions,
                extra: state.extra.clone(),
            },
        )?;
        state.dirty = false;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

const fn live(policy: &SessionPolicy, session: &Session, now: i64) -> bool {
    now < session.expires_at && now.saturating_sub(session.last_seen) < policy.idle
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_user(client: ClientKind) -> NewSession {
        NewSession {
            uid: Some(1000),
            username: Some("alice".into()),
            client,
            kind: SessionKind::User,
            method: AuthMethod::Password,
            epoch: 0,
        }
    }

    fn store(dir: &Path) -> SessionStore {
        SessionStore::load(dir.join("sessions.json"), SessionPolicy::default(), 0).unwrap()
    }

    #[test]
    fn issued_tokens_validate_and_only_hashes_are_stored() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = store(dir.path());
        let (token, session) = sessions
            .issue(new_user(ClientKind::Dashboard), 100)
            .unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(
            sessions
                .validate(&token, ClientKind::Dashboard, 101)
                .unwrap()
                .id,
            session.id
        );
        let file = fs::read_to_string(dir.path().join("sessions.json")).unwrap();
        assert!(!file.contains(&token));
        assert!(file.contains(&hash_token(&token)));
    }

    #[test]
    fn tokens_are_bound_to_their_client() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = store(dir.path());
        let (token, _) = sessions.issue(new_user(ClientKind::Dashboard), 0).unwrap();
        assert_eq!(
            sessions.validate(&token, ClientKind::Oobe, 1),
            Err(SessionError::WrongClient)
        );
    }

    #[test]
    fn sessions_expire_absolutely_and_when_idle() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = store(dir.path());
        let policy = SessionPolicy::default();
        let (token, _) = sessions.issue(new_user(ClientKind::Dashboard), 0).unwrap();
        // Used often enough to stay fresh, until the absolute lifetime ends.
        let mut now = 0;
        while now + policy.idle / 2 < policy.lifetime {
            now += policy.idle / 2;
            sessions
                .validate(&token, ClientKind::Dashboard, now)
                .unwrap();
        }
        assert_eq!(
            sessions.validate(&token, ClientKind::Dashboard, policy.lifetime),
            Err(SessionError::Expired)
        );

        let (idle, _) = sessions.issue(new_user(ClientKind::Dashboard), 0).unwrap();
        assert_eq!(
            sessions.validate(&idle, ClientKind::Dashboard, policy.idle),
            Err(SessionError::Expired)
        );
    }

    #[test]
    fn setup_sessions_use_their_own_lifetime() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = store(dir.path());
        let mut new = new_user(ClientKind::Oobe);
        new.kind = SessionKind::Setup;
        let (_, session) = sessions.issue(new, 10).unwrap();
        assert_eq!(
            session.expires_at,
            10 + SessionPolicy::default().setup_lifetime
        );
    }

    #[test]
    fn revoked_tokens_stop_working() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = store(dir.path());
        let (token, session) = sessions.issue(new_user(ClientKind::Dashboard), 0).unwrap();
        assert_eq!(sessions.revoke(|s| s.id == session.id).unwrap(), 1);
        assert_eq!(
            sessions.validate(&token, ClientKind::Dashboard, 1),
            Err(SessionError::Invalid)
        );
        assert_eq!(
            sessions.validate("not-a-token", ClientKind::Dashboard, 1),
            Err(SessionError::Invalid)
        );
    }

    #[test]
    fn last_seen_is_written_only_on_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let sessions = store(dir.path());
        let (token, _) = sessions.issue(new_user(ClientKind::Dashboard), 0).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        sessions
            .validate(&token, ClientKind::Dashboard, 60)
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), written);
        sessions.flush().unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("\"last_seen\": 60")
        );
    }

    #[test]
    fn sessions_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (token, _) = store(dir.path())
            .issue(new_user(ClientKind::Dashboard), 0)
            .unwrap();
        let reloaded = SessionStore::load(
            dir.path().join("sessions.json"),
            SessionPolicy::default(),
            10,
        )
        .unwrap();
        reloaded
            .validate(&token, ClientKind::Dashboard, 10)
            .unwrap();
    }
}
