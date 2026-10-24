//! Versioned authenticated-session protocol primitives shared by transports.
//!
//! WebSocket framing will use these types in the next transport increment. The
//! validator is transport-neutral so outbound WSS and inbound development WSS
//! cannot accidentally implement different replay rules.
use crate::prelude::*;
use ed25519_dalek::VerifyingKey;

pub const PROTOCOL_VERSION: &str = "2026-07-auth-v1";
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
pub const DEFAULT_NONCE_LIMIT: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthFrame {
    EnrollmentRequired {
        host_fingerprint: String,
    },
    Enroll {
        token: String,
        public_key: String,
    },
    Challenge {
        protocol_version: String,
        session_id: String,
        challenge: String,
        host_fingerprint: String,
    },
    Authenticate {
        protocol_version: String,
        session_id: String,
        public_key: String,
        signature: String,
        /// Host user that unprivileged actions should run as.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    ElevationStatus {
        state: ElevationState,
        expires_at: Option<i64>,
        message: Option<String>,
    },
    ElevationRequest {
        session_id: String,
    },
    ElevationRevoke {
        session_id: String,
    },
    PasswordPrompt {
        prompt_id: String,
        action_id: String,
        message: String,
        expires_at: i64,
    },
    PasswordPromptCancel {
        prompt_id: String,
        reason: String,
    },
    PasswordResponse {
        prompt_id: String,
        response: String,
    },
    PasswordCancel {
        prompt_id: String,
    },
    Command {
        session_id: String,
        sequence: u64,
        timestamp: i64,
        nonce: String,
        command: AgentCommand,
    },
    Response {
        response: super::AgentResponse,
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ElevationState {
    Inactive,
    Pending,
    Active,
    ExistingAgent,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub clock_skew_seconds: i64,
    pub nonce_limit: usize,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            nonce_limit: DEFAULT_NONCE_LIMIT,
        }
    }
}

#[derive(Debug)]
pub struct AuthenticatedSession {
    session_id: String,
    verifying_key: VerifyingKey,
    user: Option<String>,
    next_sequence: u64,
    nonces: HashSet<String>,
    nonce_order: VecDeque<String>,
    policy: SessionPolicy,
}

impl AuthenticatedSession {
    pub fn new<S: Into<String>>(
        session_id: S,
        verifying_key: VerifyingKey,
        user: Option<String>,
        policy: SessionPolicy,
    ) -> Result<Self> {
        let session_id = session_id.into();
        ensure!(!session_id.is_empty(), "session id cannot be empty");
        ensure!(
            policy.clock_skew_seconds >= 0,
            "clock skew cannot be negative"
        );
        ensure!(policy.nonce_limit > 0, "nonce limit must be positive");
        Ok(Self {
            session_id,
            verifying_key,
            user,
            next_sequence: 0,
            nonces: HashSet::new(),
            nonce_order: VecDeque::new(),
            policy,
        })
    }

    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn accept_command<'a>(
        &mut self,
        frame: &'a AuthFrame,
        now: i64,
    ) -> Result<&'a AgentCommand> {
        let AuthFrame::Command {
            session_id,
            sequence,
            timestamp,
            nonce,
            command,
        } = frame
        else {
            bail!("expected authenticated command frame")
        };

        ensure!(
            session_id == &self.session_id,
            "command session does not match"
        );
        ensure!(
            *sequence == self.next_sequence,
            "command sequence is not next"
        );
        ensure!(nonce.len() >= 16, "command nonce is too short");
        let skew = now.saturating_sub(*timestamp).abs();
        ensure!(
            skew <= self.policy.clock_skew_seconds,
            "command timestamp is outside the allowed clock skew"
        );
        ensure!(
            !self.nonces.contains(nonce),
            "command nonce has already been used"
        );

        let signature = command
            .signature
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("authenticated command is missing a signature"))?;
        verify_command_signature(
            &self.verifying_key,
            signature,
            command,
            session_id,
            *sequence,
            *timestamp,
            nonce,
        )?;

        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("command sequence exhausted"))?;
        self.nonces.insert(nonce.clone());
        self.nonce_order.push_back(nonce.clone());
        let nounces = self.nonce_order.len();
        if let excess @ 1.. = nounces.saturating_sub(self.policy.nonce_limit) {
            (self.nonce_order.drain(..excess)).for_each(|old| _ = self.nonces.remove(&old));
        }
        Ok(command)
    }
}

/// Returns the current Unix timestamp in seconds since the epoch.
///
/// # Panics
/// Panics if the system clock is before the Unix epoch.
#[must_use]
pub fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
        .try_into()
        .expect("unix_timestamp overflow when casting u64 → i64")
}

#[derive(Serialize)]
struct SignedChallenge<'a> {
    protocol_version: &'a str,
    session_id: &'a str,
    challenge: &'a str,
}

/// Canonical challenge bytes signed during authentication. A struct fixes field
/// order, avoiding JSON-map implementation differences between Rust and Node.
///
/// # Panics
///
/// Panics if the challenge struct cannot be serialized to JSON. This should
/// never happen because it only contains `&str` fields.
#[must_use]
pub fn challenge_bytes(protocol_version: &str, session_id: &str, challenge: &str) -> Vec<u8> {
    serde_json::to_vec(&SignedChallenge {
        protocol_version,
        session_id,
        challenge,
    })
    .expect("challenge fields are always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{AgentCommand, crypto::sign_command};
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn test_nonce(n: u64) -> String {
        format!("nonce-{n:012}")
    }

    fn signed_frame(key: &SigningKey, sequence: u64, timestamp: i64, nonce: &str) -> AuthFrame {
        let mut command = AgentCommand {
            id: format!("cmd-{sequence}"),
            module: "settings".into(),
            action: "get_system".into(),
            payload: json!({"b": 2, "a": 1}),
            signature: None,
            user: None,
        };
        command.signature =
            Some(sign_command(key, &command, "session-1", sequence, timestamp, nonce).unwrap());
        AuthFrame::Command {
            session_id: "session-1".into(),
            sequence,
            timestamp,
            nonce: nonce.into(),
            command,
        }
    }

    #[test]
    fn accepts_ordered_fresh_signed_commands() {
        let key = SigningKey::from_bytes(&[3_u8; 32]);
        let mut session = AuthenticatedSession::new(
            "session-1",
            key.verifying_key(),
            None,
            SessionPolicy {
                clock_skew_seconds: 300,
                nonce_limit: 2,
            },
        )
        .unwrap();
        session
            .accept_command(&signed_frame(&key, 0, 1000, &test_nonce(1)), 1000)
            .unwrap();
        session
            .accept_command(&signed_frame(&key, 1, 1001, &test_nonce(2)), 1001)
            .unwrap();
    }

    #[test]
    fn rejects_replay_wrong_sequence_and_stale_timestamp() {
        let key = SigningKey::from_bytes(&[4_u8; 32]);
        let mut session = AuthenticatedSession::new(
            "session-1",
            key.verifying_key(),
            None,
            SessionPolicy::default(),
        )
        .unwrap();
        let first = signed_frame(&key, 0, 1000, &test_nonce(1));
        session.accept_command(&first, 1000).unwrap();
        session.accept_command(&first, 1000).unwrap_err();
        session
            .accept_command(&signed_frame(&key, 2, 1000, &test_nonce(2)), 1000)
            .unwrap_err();
        session
            .accept_command(&signed_frame(&key, 1, 0, &test_nonce(3)), 1000)
            .unwrap_err();
    }

    #[test]
    fn nonce_cache_is_bounded() {
        let key = SigningKey::from_bytes(&[5_u8; 32]);
        let mut session = AuthenticatedSession::new(
            "session-1",
            key.verifying_key(),
            None,
            SessionPolicy {
                clock_skew_seconds: 300,
                nonce_limit: 1,
            },
        )
        .unwrap();
        session
            .accept_command(&signed_frame(&key, 0, 1000, &test_nonce(1)), 1000)
            .unwrap();
        session
            .accept_command(&signed_frame(&key, 1, 1000, &test_nonce(2)), 1000)
            .unwrap();
        assert_eq!(session.nonces.len(), 1);
    }
}
