//! Password verification through PAM.
//!
//! Dashboard logins use the dedicated `ultramarine-dashboard` PAM service
//! (`pam/ultramarine-dashboard`, installed to `/etc/pam.d`), which stacks
//! `pam_faillock` around `pam_unix` so repeated wrong passwords lock the
//! account for the dashboard. The tally lives in its own directory
//! ([`FAILLOCK_DIR`]), so dashboard failures never lock console or SSH logins.
//! Tetra runs `pam_authenticate` followed by `pam_acct_mgmt`; passkey logins
//! run only the account stack, which has no `pam_faillock`, so expiry and
//! `/etc/nologin` still apply but a password lockout does not.
//!
//! PAM calls block (and `pam_unix` deliberately delays failures), so callers
//! run them on the blocking thread pool.

use pam_client::{Context, ErrorCode, Flag, conv_mock, conv_null};

use crate::prelude::*;

/// Default PAM service name, matching `/etc/pam.d/ultramarine-dashboard`.
pub const DEFAULT_SERVICE: &str = "ultramarine-dashboard";
/// Name of the dashboard's `pam_faillock` tally directory under the state
/// directory (`dir=` in the PAM service file).
pub const FAILLOCK_DIR: &str = "faillock";

/// Result of a PAM transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PamOutcome {
    Success,
    /// Wrong password, unknown user, faillock lockout (password logins only)
    /// or an account-stack denial. Deliberately not distinguished.
    Denied,
    /// The password was correct but has expired; it must be changed on the
    /// console or over SSH.
    PasswordExpired,
    /// PAM itself failed (misconfiguration, missing module).
    Error(String),
}

/// Verifies passwords and account state. [`LibPam`] in production.
pub trait PasswordBackend: Send + Sync {
    /// Run the auth and account stacks for `username` with `password`.
    fn authenticate(&self, username: &str, password: &str, rhost: Option<&str>) -> PamOutcome;
    /// Run only the account stack, for logins that did not use a password.
    fn check_account(&self, username: &str, rhost: Option<&str>) -> PamOutcome;
}

/// [`PasswordBackend`] backed by the system libpam.
#[derive(Debug, Clone)]
pub struct LibPam {
    pub service: String,
}

impl Default for LibPam {
    fn default() -> Self {
        Self {
            service: DEFAULT_SERVICE.to_owned(),
        }
    }
}

fn outcome(result: Result<(), pam_client::Error>) -> PamOutcome {
    match result {
        Ok(()) => PamOutcome::Success,
        Err(error) => match error.code() {
            ErrorCode::NEW_AUTHTOK_REQD | ErrorCode::AUTHTOK_EXPIRED => PamOutcome::PasswordExpired,
            ErrorCode::AUTH_ERR
            | ErrorCode::USER_UNKNOWN
            | ErrorCode::MAXTRIES
            | ErrorCode::PERM_DENIED
            | ErrorCode::ACCT_EXPIRED
            | ErrorCode::CRED_INSUFFICIENT
            | ErrorCode::AUTHINFO_UNAVAIL => PamOutcome::Denied,
            _ => PamOutcome::Error(error.to_string()),
        },
    }
}

impl PasswordBackend for LibPam {
    fn authenticate(&self, username: &str, password: &str, rhost: Option<&str>) -> PamOutcome {
        let conversation = conv_mock::Conversation::with_credentials(username, password);
        let mut context = match Context::new(&self.service, Some(username), conversation) {
            Ok(context) => context,
            Err(error) => return PamOutcome::Error(error.to_string()),
        };
        if let Err(error) = context.set_rhost(rhost) {
            return PamOutcome::Error(error.to_string());
        }
        match outcome(context.authenticate(Flag::DISALLOW_NULL_AUTHTOK)) {
            PamOutcome::Success => outcome(context.acct_mgmt(Flag::DISALLOW_NULL_AUTHTOK)),
            other => other,
        }
    }

    fn check_account(&self, username: &str, rhost: Option<&str>) -> PamOutcome {
        let conversation = conv_null::Conversation::new();
        let mut context = match Context::new(&self.service, Some(username), conversation) {
            Ok(context) => context,
            Err(error) => return PamOutcome::Error(error.to_string()),
        };
        if let Err(error) = context.set_rhost(rhost) {
            return PamOutcome::Error(error.to_string());
        }
        outcome(context.acct_mgmt(Flag::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::FAILLOCK_DIR;

    #[test]
    fn pam_service_file_uses_faillock_around_pam_unix() {
        let file = include_str!("../../pam/ultramarine-dashboard");
        // Its own tally, never the one console and SSH logins share.
        let tally = format!("dir=/var/lib/tetra/{FAILLOCK_DIR}");
        for line in file.lines().filter(|line| line.contains("pam_faillock.so")) {
            assert!(
                line.starts_with("auth") && line.contains(&tally),
                "`{line}` must be in the auth stack and use {tally}"
            );
        }
        let auth: Vec<_> = file
            .lines()
            .filter(|line| line.starts_with("auth"))
            .collect();
        let position = |needle: &str| auth.iter().position(|line| line.contains(needle));
        let preauth = position("pam_faillock.so preauth").unwrap();
        let unix = position("pam_unix.so").unwrap();
        let authfail = position("pam_faillock.so authfail").unwrap();
        assert!(preauth < unix && unix < authfail);
        assert!(!file.contains("nullok"), "empty passwords must not log in");
        assert!(
            file.lines()
                .any(|line| line.starts_with("account") && line.contains("pam_unix.so"))
        );
    }
}
