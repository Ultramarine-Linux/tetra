//! Login: `auth.*` (password, second factor, passkey).

use std::sync::Arc;

use serde_json::json;
use webauthn_rs::prelude::{AuthenticationResult, DiscoverableKey, Passkey, PublicKeyCredential};

use crate::{
    auth::{
        accounts::Account,
        api::{ApiError, ApiResult, ErrorCode},
        pam::{PamOutcome, PasswordBackend},
        passkey::{self, Authentication, AuthenticationState, CEREMONY_TTL},
        recovery,
        sessions::{AuthMethod, ClientKind},
        totp,
        users::UserRecord,
    },
    prelude::*,
};

use super::{
    AuthService, PendingLogin, SECOND_FACTOR_ATTEMPTS, blocking, json_value, totp_purpose,
    user_owner,
};

/// Seconds between the password and the second factor.
const LOGIN_TTL: i64 = 300;
/// Consecutive wrong second-factor codes per account, across logins, before
/// each further attempt has to wait.
const SECOND_FACTOR_FREE_FAILURES: u32 = 10;
/// Longest wait between second-factor attempts per account, in seconds.
const SECOND_FACTOR_MAX_BACKOFF: i64 = 900;

impl AuthService {
    // --- Login -----------------------------------------------------------

    pub(super) async fn auth_password(&self, client: ClientKind, p: PasswordParams) -> ApiResult {
        let PasswordParams {
            username,
            password,
            remote_addr,
        } = p;
        if !plausible_username(&username) || password.is_empty() {
            return Err(ApiError::invalid_credentials());
        }
        let name = username.clone();
        let rhost = passkey::client_ip(remote_addr.as_deref()).map(|ip| ip.to_string());
        let outcome = self
            .pam(move |passwords| passwords.authenticate(&name, &password, rhost.as_deref()))
            .await?;
        match &outcome {
            PamOutcome::Denied => {
                eprintln!("password login failed for `{username}`");
                return Err(ApiError::invalid_credentials());
            }
            PamOutcome::PasswordExpired | PamOutcome::Success => {}
            PamOutcome::Error(error) => {
                return Err(anyhow::anyhow!("PAM failed: {error}").into());
            }
        }
        let expired = outcome == PamOutcome::PasswordExpired;
        let this = self.clone();
        blocking(move || this.finish_password_login(client, &username, expired)).await?
    }

    /// The rest of `auth.password` once PAM accepted the password (`expired`
    /// or not), on the blocking pool: it reads the user record and writes
    /// the session file.
    fn finish_password_login(
        &self,
        client: ClientKind,
        username: &str,
        expired: bool,
    ) -> ApiResult {
        // Eligibility is checked after PAM so that failures take the same
        // time whether or not the account exists, and before reporting an
        // expired password so that root and other accounts that may never log
        // in do not learn that a guess was right.
        let Some(account) = self.eligible_by_name(username)? else {
            return Err(ApiError::invalid_credentials());
        };
        if expired {
            return Err(ApiError::new(
                ErrorCode::PasswordExpired,
                "the password has expired; change it on the console or over SSH",
            ));
        }
        let enrolled = self
            .record(account.uid, &account.name)?
            .is_some_and(|record| record.totp.is_some());
        if !enrolled {
            return self.issue_user_session(client, &account, AuthMethod::Password);
        }
        let now = self.now();
        let expires_at = now.saturating_add(LOGIN_TTL);
        let pending = self
            .inner
            .logins
            .insert(
                Some(&user_owner(account.uid)),
                PendingLogin {
                    client,
                    uid: account.uid,
                    username: account.name,
                    attempts: 0,
                    expires_at,
                },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(LOGIN_TTL))?;
        Ok(json!({
            "status": "second_factor_required",
            "pending": pending,
            "methods": ["totp", "recovery_code"],
            "expires_at": expires_at,
        }))
    }

    /// Run a PAM transaction on the blocking pool, at most
    /// [`PAM_CONCURRENCY`](super::PAM_CONCURRENCY) at a time.
    async fn pam(
        &self,
        run: impl FnOnce(&dyn PasswordBackend) -> PamOutcome + Send + 'static,
    ) -> Result<PamOutcome, ApiError> {
        let _permit = self
            .inner
            .pam
            .acquire()
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let passwords = Arc::clone(&self.inner.passwords);
        blocking(move || run(passwords.as_ref())).await
    }

    /// Check a TOTP code or recovery code against `record`, consuming it.
    ///
    /// Wrong TOTP codes are counted on the record, across logins, so knowing
    /// the password does not give unlimited guesses at the 6-digit code: after
    /// [`SECOND_FACTOR_FREE_FAILURES`] each attempt waits twice as long as the
    /// last, up to [`SECOND_FACTOR_MAX_BACKOFF`], and fails with
    /// [`SecondFactorError::Locked`] meanwhile. Recovery codes (50 bits each) are too
    /// strong to guess and stay usable during the wait, so someone holding
    /// the password cannot lock the real user out of their account with it.
    pub(super) fn verify_second_factor(
        &self,
        record: &mut UserRecord,
        code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<Option<AuthMethod>> {
        let now = self.now();
        if code.is_some() && now < record.second_factor_retry_at {
            bail!(SecondFactorError::Locked {
                retry_after: record.second_factor_retry_at.saturating_sub(now),
            });
        }
        let method = self.check_second_factor(record, code, recovery_code, now)?;
        if method.is_some() {
            record.second_factor_failures = 0;
            record.second_factor_retry_at = 0;
        } else if code.is_some() {
            record.second_factor_failures = record.second_factor_failures.saturating_add(1);
            if let Some(excess) = record
                .second_factor_failures
                .checked_sub(SECOND_FACTOR_FREE_FAILURES)
            {
                let backoff = 2_i64
                    .checked_pow(excess)
                    .map_or(SECOND_FACTOR_MAX_BACKOFF, |wait| {
                        wait.min(SECOND_FACTOR_MAX_BACKOFF)
                    });
                record.second_factor_retry_at = now.saturating_add(backoff);
            }
        }
        Ok(method)
    }

    fn check_second_factor(
        &self,
        record: &mut UserRecord,
        code: Option<&str>,
        recovery_code: Option<&str>,
        now: i64,
    ) -> Result<Option<AuthMethod>> {
        match (code, recovery_code) {
            (Some(code), None) => {
                let Some(totp_record) = record.totp.as_mut() else {
                    return Ok(None);
                };
                let key = self.key()?;
                let secret = key.decrypt(&totp_purpose(record.uid), &totp_record.secret)?;
                Ok(
                    totp::verify(&secret, code, now, totp_record.last_step).map(|step| {
                        totp_record.last_step = Some(step);
                        AuthMethod::PasswordTotp
                    }),
                )
            }
            (None, Some(recovery_code)) => Ok((record.totp.is_some()
                && recovery::redeem(&mut record.recovery_codes, recovery_code, now))
            .then_some(AuthMethod::PasswordRecoveryCode)),
            _ => bail!(SecondFactorError::Bad),
        }
    }

    pub(super) fn auth_second_factor(
        &self,
        client: ClientKind,
        p: SecondFactorParams,
    ) -> ApiResult {
        let now = self.now();
        let Some(mut login) = self.inner.logins.take(&p.pending, now) else {
            return Err(ApiError::new(
                ErrorCode::InvalidCredentials,
                "the login has expired; enter the password again",
            ));
        };
        if login.client != client {
            return Err(ApiError::invalid_credentials());
        }
        let Some(account) = self.eligible_by_uid(login.uid, &login.username)? else {
            return Err(ApiError::invalid_credentials());
        };
        let verified = self
            .inner
            .users
            .update(login.uid, &login.username, |record| {
                self.verify_second_factor(record, p.code.as_deref(), p.recovery_code.as_deref())
            });
        let error = match verified {
            Ok(Some(method)) => return self.issue_user_session(client, &account, method),
            Ok(None) => {
                eprintln!("second factor failed for `{}`", login.username);
                login.attempts = login.attempts.saturating_add(1);
                ApiError::invalid_credentials()
            }
            Err(error) => second_factor_error(error),
        };
        // The same login may be retried, unless its attempts are used up or
        // Tetra itself failed.
        if login.attempts < SECOND_FACTOR_ATTEMPTS && error.code != ErrorCode::Internal {
            let expires_at = login.expires_at;
            self.inner.logins.restore(
                p.pending,
                Some(&user_owner(login.uid)),
                login,
                expires_at,
                now,
            );
        }
        Err(error)
    }

    pub(super) fn auth_passkey_begin(
        &self,
        client: ClientKind,
        p: &PasskeyBeginParams,
    ) -> ApiResult {
        let webauthn = self.webauthn()?;
        let known = match p.username.as_deref() {
            Some(name) => self.eligible_by_name(name)?.and_then(|account| {
                // A store error takes the decoy path like an unknown user,
                // but is not silent.
                let record = self
                    .record(account.uid, &account.name)
                    .inspect_err(|error| {
                        eprintln!("passkey login for `{}`: {}", account.name, error.message);
                    })
                    .ok()??;
                (!record.passkeys.is_empty()).then_some((account, record))
            }),
            None => None,
        };
        let (options, state) = if let Some((account, record)) = known {
            let keys: Vec<Passkey> = record.passkeys.iter().map(|p| p.passkey.clone()).collect();
            let (options, state) = webauthn
                .start_passkey_authentication(&keys)
                .map_err(|error| anyhow::anyhow!("webauthn: {error}"))?;
            let state = AuthenticationState::Known {
                uid: account.uid,
                username: account.name,
                state,
            };
            (options, state)
        } else {
            let (mut options, state) = webauthn
                .start_discoverable_authentication()
                .map_err(|error| anyhow::anyhow!("webauthn: {error}"))?;
            if p.username.is_some() || !p.conditional {
                options.mediation = None;
            }
            (options, AuthenticationState::Discoverable(state))
        };
        let mut options = json_value(&options);
        if let (Some(name), AuthenticationState::Discoverable(_)) = (p.username.as_deref(), &state)
        {
            // Answer like a user with one passkey, so the response does not
            // reveal whether `name` exists or has passkeys. No authenticator
            // holds the decoy, so the ceremony cannot complete.
            let seed = self
                .key()?
                .keyed_hash(passkey::DECOY_PURPOSE, name.as_bytes());
            options["publicKey"]["allowCredentials"] =
                Value::Array(vec![passkey::decoy_credential(&seed)]);
        }
        let now = self.now();
        let expires_at = now.saturating_add(CEREMONY_TTL);
        let ceremony = self
            .inner
            .authentications
            .insert(
                passkey::source_owner(p.remote_addr.as_deref()).as_deref(),
                Authentication { client, state },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(CEREMONY_TTL))?;
        Ok(json!({ "ceremony": ceremony, "options": options, "expires_at": expires_at }))
    }

    pub(super) async fn auth_passkey_finish(
        &self,
        client: ClientKind,
        p: PasskeyFinishParams,
    ) -> ApiResult {
        let now = self.now();
        let remote_addr = p.remote_addr.clone();
        let this = self.clone();
        let (account, uid, username, result) =
            blocking(move || this.identify_passkey(client, &p, now)).await??;
        let name = account.name.clone();
        let rhost = passkey::client_ip(remote_addr.as_deref()).map(|ip| ip.to_string());
        let outcome = self
            .pam(move |passwords| passwords.check_account(&name, rhost.as_deref()))
            .await?;
        match outcome {
            // An expired password does not stop a passwordless login.
            PamOutcome::Success | PamOutcome::PasswordExpired => {}
            PamOutcome::Denied => {
                eprintln!("passkey login refused by PAM account stack for `{username}`");
                return Err(ApiError::invalid_credentials());
            }
            PamOutcome::Error(error) => return Err(anyhow::anyhow!("PAM failed: {error}").into()),
        }
        let this = self.clone();
        blocking(move || this.finish_passkey_login(client, &account, uid, &username, &result, now))
            .await?
    }

    /// The first half of `auth.passkey_finish`, on the blocking pool: check
    /// the assertion of `p`'s ceremony and find its eligible account.
    fn identify_passkey(
        &self,
        client: ClientKind,
        p: &PasskeyFinishParams,
        now: i64,
    ) -> Result<(Account, u32, String, AuthenticationResult), ApiError> {
        let webauthn = self.webauthn()?;
        let Some(ceremony) = self
            .inner
            .authentications
            .take(&p.ceremony, now)
            .filter(|ceremony| ceremony.client == client)
        else {
            return Err(ApiError::invalid_credentials());
        };
        let failed = |error: webauthn_rs::prelude::WebauthnError| {
            eprintln!("passkey login failed: {error}");
            ApiError::invalid_credentials()
        };
        let (uid, username, result) = match ceremony.state {
            AuthenticationState::Known {
                uid,
                username,
                state,
            } => {
                let result = webauthn
                    .finish_passkey_authentication(&p.credential, &state)
                    .map_err(failed)?;
                (uid, username, result)
            }
            AuthenticationState::Discoverable(state) => {
                let (handle, _) = webauthn
                    .identify_discoverable_authentication(&p.credential)
                    .map_err(failed)?;
                let Some(record) = self
                    .inner
                    .users
                    .all()?
                    .into_iter()
                    .find(|record| record.webauthn_id == Some(handle))
                else {
                    return Err(ApiError::invalid_credentials());
                };
                let keys: Vec<DiscoverableKey> = record
                    .passkeys
                    .iter()
                    .map(|p| (&p.passkey).into())
                    .collect();
                let result = webauthn
                    .finish_discoverable_authentication(&p.credential, state, &keys)
                    .map_err(failed)?;
                (record.uid, record.username, result)
            }
        };

        // A passkey proves who the user is, not that the account may still
        // log in: check eligibility (and the caller runs PAM's account stack).
        let Some(account) = self.eligible_by_uid(uid, &username)? else {
            return Err(ApiError::invalid_credentials());
        };
        Ok((account, uid, username, result))
    }

    /// The rest of `auth.passkey_finish` once PAM's account stack allowed
    /// the login, on the blocking pool: record the passkey's use and issue
    /// the session.
    fn finish_passkey_login(
        &self,
        client: ClientKind,
        account: &Account,
        uid: u32,
        username: &str,
        result: &AuthenticationResult,
        now: i64,
    ) -> ApiResult {
        let updated = self.inner.users.update(uid, username, |record| {
            let stored = record
                .passkeys
                .iter_mut()
                .find(|stored| stored.passkey.cred_id() == result.cred_id())
                .context("the passkey was removed")?;
            stored.passkey.update_credential(result);
            stored.last_used_at = Some(now);
            Ok(())
        });
        if let Err(error) = updated {
            eprintln!("passkey login for `{username}` failed: {error:#}");
            return Err(ApiError::invalid_credentials());
        }
        self.issue_user_session(client, account, AuthMethod::Passkey)
    }
}

/// Whether `name` could be an account name worth asking PAM about. Control
/// characters would also let a caller forge lines in the journal.
fn plausible_username(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
}

/// Second-factor failures that are not a wrong code, raised inside a
/// [`UserStore::update`](crate::auth::users::UserStore::update) and mapped by
/// [`second_factor_error`].
#[derive(Debug)]
pub(super) enum SecondFactorError {
    /// Neither or both of `code` and `recovery_code`.
    Bad,
    /// Too many wrong codes.
    Locked {
        retry_after: i64,
    },
    NotEnrolled,
    AlreadyEnrolled,
}

impl std::fmt::Display for SecondFactorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bad => f.write_str("pass exactly one of `code` or `recovery_code`"),
            Self::Locked { retry_after } => {
                write!(f, "too many wrong codes; retry in {retry_after} seconds")
            }
            Self::NotEnrolled => f.write_str("TOTP is not enrolled"),
            Self::AlreadyEnrolled => f.write_str("TOTP is already enrolled; disable it first"),
        }
    }
}

impl std::error::Error for SecondFactorError {}

/// The API error for a failed second-factor update.
pub(super) fn second_factor_error(error: anyhow::Error) -> ApiError {
    match error.downcast::<SecondFactorError>() {
        Ok(SecondFactorError::Locked { retry_after }) => ApiError::rate_limited(retry_after),
        Ok(error @ SecondFactorError::Bad) => ApiError::bad_request(error),
        Ok(error @ SecondFactorError::NotEnrolled) => {
            ApiError::new(ErrorCode::NotFound, error.to_string())
        }
        Ok(error @ SecondFactorError::AlreadyEnrolled) => {
            ApiError::new(ErrorCode::Conflict, error.to_string())
        }
        Err(error) => error.into(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasswordParams {
    username: String,
    password: String,
    /// The browser's address, for PAM (`PAM_RHOST`) and logs.
    #[serde(default)]
    remote_addr: Option<String>,
}

impl std::fmt::Debug for PasswordParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordParams")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecondFactorParams {
    pending: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyBeginParams {
    #[serde(default)]
    username: Option<String>,
    /// The browser's address. Pending ceremonies are limited per address.
    #[serde(default)]
    remote_addr: Option<String>,
    /// Keep conditional mediation (autofill UI) on a usernameless challenge.
    #[serde(default)]
    conditional: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyFinishParams {
    ceremony: String,
    credential: PublicKeyCredential,
    #[serde(default)]
    remote_addr: Option<String>,
}
