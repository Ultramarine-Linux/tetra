//! TOTP second factor (RFC 6238).
//!
//! SHA-1, 6 digits, 30-second steps, one step of clock skew either way. These are the parameters every authenticator app
//! supports. A code is accepted at most once: the last accepted step is
//! stored and anything at or before it is rejected.

use totp_rs::{Builder, Secret, Totp};

use crate::prelude::*;

/// Shown by authenticator apps next to the account name.
pub const ISSUER: &str = "Ultramarine Server";
const SECRET_BYTES: usize = 20;

/// A fresh random shared secret.
#[must_use]
pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0_u8; SECRET_BYTES];
    rand::fill(&mut secret[..]);
    secret
}

fn totp(secret: &[u8], account: &str) -> Result<Totp> {
    Builder::new()
        .with_secret(secret.to_vec())
        .with_account_name(account.replace(':', "_"))
        .with_issuer(Some(ISSUER))
        .build()
        .map_err(|error| anyhow::anyhow!("invalid TOTP parameters: {error}"))
}

/// Base32 secret for manual entry.
#[must_use]
pub fn secret_base32(secret: &[u8]) -> String {
    Secret::from(secret.to_vec()).to_base32()
}

/// `otpauth://` URI for QR codes.
///
/// # Errors
/// Fails when the secret is too short.
pub fn otpauth_uri(secret: &[u8], account: &str) -> Result<String> {
    totp(secret, account)?
        .to_url()
        .map_err(|error| anyhow::anyhow!("failed to build otpauth URI: {error}"))
}

/// Check `code` at `now`. Returns the matched time step, which the caller
/// must store as the new `last_step`, or `None` when the code is wrong or was
/// already used.
#[must_use]
pub fn verify(secret: &[u8], code: &str, now: i64, last_step: Option<u64>) -> Option<u64> {
    let code: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    let now = u64::try_from(now).ok()?;
    let step = totp(secret, "").ok()?.check(&code, now)?;
    last_step.is_none_or(|last| step > last).then_some(step)
}

/// The code for `now`. Used by tests.
///
/// # Errors
/// Fails when the secret is too short.
pub fn code_at(secret: &[u8], now: i64) -> Result<String> {
    let now = u64::try_from(now).context("time before the epoch")?;
    Ok(totp(secret, "")?.generate(now).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn accepts_current_and_adjacent_codes() {
        let secret = generate_secret();
        for offset in [-30, 0, 30] {
            let code = code_at(&secret, NOW + offset).unwrap();
            assert!(
                verify(&secret, &code, NOW, None).is_some(),
                "offset {offset}"
            );
        }
        let stale = code_at(&secret, NOW - 90).unwrap();
        assert!(verify(&secret, &stale, NOW, None).is_none());
    }

    #[test]
    fn a_code_is_accepted_only_once() {
        let secret = generate_secret();
        let code = code_at(&secret, NOW).unwrap();
        let step = verify(&secret, &code, NOW, None).unwrap();
        assert!(verify(&secret, &code, NOW, Some(step)).is_none());
        // An older code is also refused after a newer one was used.
        let previous = code_at(&secret, NOW - 30).unwrap();
        assert!(verify(&secret, &previous, NOW, Some(step)).is_none());
    }

    #[test]
    fn rejects_wrong_codes_and_tolerates_spaces() {
        let secret = generate_secret();
        assert!(verify(&secret, "000000x", NOW, None).is_none());
        let code = code_at(&secret, NOW).unwrap();
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify(&secret, &spaced, NOW, None).is_some());
    }

    #[test]
    fn builds_an_otpauth_uri() {
        let uri = otpauth_uri(&generate_secret(), "alice").unwrap();
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(uri.contains("alice"));
    }
}
