//! Cryptographic primitives for authenticated controller/agent messages.
//!
//! This module intentionally does not enforce signatures yet. Transport
//! negotiation will select a key and then call these helpers before dispatch.
//! Keeping canonicalization here prevents vsock and WebSocket paths from
//! accidentally signing different representations of the same command.

use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::{Value, to_vec};

use super::AgentCommand;

/// The signed message format version. It is separate from the transport version
/// so a transport can evolve without silently changing command signatures.
pub const SIGNING_VERSION: &str = "tetra-command-v1";

/// Fields bound into a command signature. `payload` is serialized as canonical
/// JSON by recursively sorting object keys.
#[derive(Debug, Serialize)]
struct SignedCommand<'a> {
    version: &'static str,
    session_id: &'a str,
    sequence: u64,
    timestamp: i64,
    nonce: &'a str,
    id: &'a str,
    module: &'a str,
    action: &'a str,
    payload: Value,
}

/// Produce the exact bytes that Ed25519 signs and verifies.
///
/// # Errors
/// Errs if `session_id` or `nonce` is empty.
pub fn canonical_command_bytes(
    command: &AgentCommand,
    session_id: &str,
    sequence: u64,
    timestamp: i64,
    nonce: &str,
) -> Result<Vec<u8>> {
    ensure!(!session_id.is_empty(), "session id cannot be empty");
    ensure!(!nonce.is_empty(), "nonce cannot be empty");

    to_vec(&SignedCommand {
        version: SIGNING_VERSION,
        session_id,
        sequence,
        timestamp,
        nonce,
        id: &command.id,
        module: &command.module,
        action: &command.action,
        payload: canonicalize(command.payload.clone()),
    })
    .map_err(Into::into)
}

/// Sign a command context and return an URL-safe base64 signature.
///
/// # Errors
/// Propagated from [`canonical_command_bytes`]:
/// > Errs if `session_id` or `nonce` is empty.
pub fn sign_command(
    signing_key: &SigningKey,
    command: &AgentCommand,
    session_id: &str,
    sequence: u64,
    timestamp: i64,
    nonce: &str,
) -> Result<String> {
    let bytes = canonical_command_bytes(command, session_id, sequence, timestamp, nonce)?;
    Ok(URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes()))
}

/// Sign a connection challenge during WebSocket authentication.
#[must_use]
pub fn sign_challenge(
    signing_key: &SigningKey,
    protocol_version: &str,
    session_id: &str,
    challenge: &str,
) -> String {
    URL_SAFE_NO_PAD.encode(
        signing_key
            .sign(&crate::agent::protocol::challenge_bytes(
                protocol_version,
                session_id,
                challenge,
            ))
            .to_bytes(),
    )
}

/// Verify a dashboard signature over a connection challenge.
///
/// # Errors
/// An error is returned if the signature is invalid, or the verification failed.
pub fn verify_challenge_signature(
    verifying_key: &VerifyingKey,
    signature: &str,
    protocol_version: &str,
    session_id: &str,
    challenge: &str,
) -> Result<()> {
    let signature = decode_signature(signature)?;
    verifying_key
        .verify(
            &crate::agent::protocol::challenge_bytes(protocol_version, session_id, challenge),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("challenge signature verification failed"))
}

/// Verify an URL-safe base64 Ed25519 signature.
///
/// # Errors
/// An error is returned if the signature is invalid, or the verification failed.
pub fn verify_command_signature(
    verifying_key: &VerifyingKey,
    signature: &str,
    command: &AgentCommand,
    session_id: &str,
    sequence: u64,
    timestamp: i64,
    nonce: &str,
) -> Result<()> {
    let signature = decode_signature(signature)?;
    let bytes = canonical_command_bytes(command, session_id, sequence, timestamp, nonce)?;
    verifying_key
        .verify(&bytes, &signature)
        .map_err(|_| anyhow::anyhow!("command signature verification failed"))
}

fn decode_signature(signature: &str) -> Result<Signature, anyhow::Error> {
    let encoded = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| anyhow::anyhow!("command signature is not valid base64url"))?;
    let signature = Signature::from_slice(&encoded)
        .map_err(|_| anyhow::anyhow!("command signature has invalid length"))?;
    Ok(signature)
}

/// Recursively sort JSON object keys. Arrays retain their order because array
/// order is part of a command payload's meaning.
fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = serde_json::Map::new();
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in entries {
                sorted.insert(key, canonicalize(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

/// Return a compact public-key fingerprint for enrollment and logs.
#[must_use]
pub fn public_key_fingerprint(verifying_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
}

/// Parse a URL-safe base64 public key.
///
/// # Errors
/// Returns and error if the public key is not valid base64url or does not contain 32 bytes.
pub fn parse_verifying_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("public key is not valid base64url"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must contain 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn command(payload: Value) -> AgentCommand {
        AgentCommand {
            id: "cmd-1".into(),
            module: "settings".into(),
            action: "get_system".into(),
            payload,
            signature: None,
            user: None,
        }
    }

    #[test]
    fn canonicalization_is_independent_of_object_key_order() {
        let nonce = format!("nonce-{}", 1);
        let left = canonical_command_bytes(
            &command(json!({"z": 1, "a": {"y": true, "b": false}})),
            "session-1",
            1,
            1_700_000_000,
            &nonce,
        )
        .unwrap();
        let right = canonical_command_bytes(
            &command(json!({"a": {"b": false, "y": true}, "z": 1})),
            "session-1",
            1,
            1_700_000_000,
            &nonce,
        )
        .unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn signatures_round_trip_and_bind_context() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let command = command(json!({"value": 42}));
        let nonce = format!("nonce-{}", 1);
        let signature = sign_command(&signing_key, &command, "session-1", 1, 100, &nonce).unwrap();

        verify_command_signature(
            &verifying_key,
            &signature,
            &command,
            "session-1",
            1,
            100,
            &nonce,
        )
        .unwrap();
        verify_command_signature(
            &verifying_key,
            &signature,
            &command,
            "session-1",
            2,
            100,
            &nonce,
        )
        .unwrap_err();
    }

    #[test]
    fn public_key_round_trips() {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let encoded = public_key_fingerprint(&signing_key.verifying_key());
        let parsed = parse_verifying_key(&encoded).unwrap();
        assert_eq!(parsed, signing_key.verifying_key());
    }
}
