//! The caller's own sessions and account: `session.*` and `account.*`
//! (TOTP, recovery codes, passkey registration).

use serde_json::json;
use webauthn_rs::prelude::{RegisterPublicKeyCredential, Uuid};

use crate::{
    auth::{
        accounts::AccountSource,
        api::{ApiError, ApiResult, ErrorCode},
        authz::{self, Principal},
        passkey::{self, CEREMONY_TTL, Registration},
        recovery,
        sessions::SessionKind,
        totp,
        users::{PasskeyRecord, TotpRecord, UserRecord, UserStore},
    },
    prelude::*,
};

use super::{
    AuthService, Caller, PendingTotp, SECOND_FACTOR_ATTEMPTS, UidParams, json_value,
    login::{SecondFactorError, second_factor_error},
    session_json, totp_purpose, user_owner,
};

/// Seconds to confirm a TOTP enrollment.
const ENROLLMENT_TTL: i64 = 600;
const MAX_PASSKEY_NAME: usize = 64;

impl AuthService {
    // --- Sessions --------------------------------------------------------

    pub(super) fn session_info(caller: &Caller) -> Value {
        let user = match &caller.principal {
            Principal::User {
                uid,
                username,
                admin,
                ..
            } => json!({ "uid": uid, "username": username, "admin": admin }),
            _ => Value::Null,
        };
        let permissions = match &caller.principal {
            Principal::User { admin: true, .. } => json!({ "all": true }),
            Principal::User { permissions, .. } => json_value(permissions),
            Principal::Setup => {
                json!({
                    "setup": authz::SETUP_ALLOWED.iter().map(|(m, a)| format!("{m}.{a}")).collect::<Vec<_>>(),
                    "operations": authz::SETUP_OPERATIONS,
                })
            }
            Principal::RemoteController => Value::Null,
        };
        json!({
            "session": session_json(&caller.session, Some(&caller.session)),
            "user": user,
            "permissions": permissions,
        })
    }

    pub(super) fn session_logout(&self, caller: &Caller) -> ApiResult {
        let id = caller.session.id.clone();
        self.inner.sessions.revoke(|session| session.id == id)?;
        Ok(json!({ "revoked": 1 }))
    }

    pub(super) fn session_list(&self, caller: &Caller, p: UidParams) -> ApiResult {
        let (own, _) = caller.user()?;
        let uid = p.uid.unwrap_or(own);
        if uid != own {
            caller.require_admin()?;
        }
        let sessions: Vec<Value> = self
            .inner
            .sessions
            .list(|session| session.uid == Some(uid), self.now())
            .iter()
            .map(|session| session_json(session, Some(&caller.session)))
            .collect();
        Ok(json!({ "sessions": sessions }))
    }

    pub(super) fn session_revoke(&self, caller: &Caller, p: &SessionIdParams) -> ApiResult {
        let (own, _) = caller.user()?;
        let admin = caller.is_admin();
        let revoked = self.inner.sessions.revoke(|session| {
            session.id == p.id
                && session.kind == SessionKind::User
                && (admin || session.uid == Some(own))
        })?;
        if revoked == 0 {
            return Err(ApiError::new(ErrorCode::NotFound, "no such session"));
        }
        Ok(json!({ "revoked": revoked }))
    }

    // --- Second factor ---------------------------------------------------

    pub(super) fn account_status(&self, caller: &Caller) -> ApiResult {
        let (uid, username) = caller.user()?;
        let record = self.record(uid, username)?;
        Ok(json!({
            "totp_enrolled": record.as_ref().is_some_and(|r| r.totp.is_some()),
            "recovery_codes_left": record.as_ref().map_or(0, UserRecord::recovery_codes_left),
            "passkeys": record.as_ref().map_or(0, |r| r.passkeys.len()),
            "passkeys_available": self.webauthn().is_ok(),
        }))
    }

    pub(super) fn totp_begin(&self, caller: &Caller) -> ApiResult {
        let (uid, username) = caller.user()?;
        self.require_recent_login(caller)?;
        if self
            .record(uid, username)?
            .is_some_and(|record| record.totp.is_some())
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "TOTP is already enrolled; disable it first",
            ));
        }
        let secret = totp::generate_secret();
        let otpauth_uri = totp::otpauth_uri(&secret, username)?;
        let secret_base32 = totp::secret_base32(&secret);
        let now = self.now();
        let expires_at = now.saturating_add(ENROLLMENT_TTL);
        let enrollment = self
            .inner
            .enrollments
            .insert(
                Some(&user_owner(uid)),
                PendingTotp {
                    client: caller.client,
                    uid,
                    secret,
                    attempts: 0,
                    expires_at,
                },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(ENROLLMENT_TTL))?;
        Ok(
            json!({ "enrollment": enrollment, "secret": secret_base32, "otpauth_uri": otpauth_uri, "expires_at": expires_at }),
        )
    }

    pub(super) fn totp_confirm(&self, caller: &Caller, p: TotpConfirmParams) -> ApiResult {
        let (uid, username) = caller.user()?;
        let now = self.now();
        let Some(mut pending) = self
            .inner
            .enrollments
            .take(&p.enrollment, now)
            .filter(|pending| pending.uid == uid && pending.client == caller.client)
        else {
            return Err(ApiError::new(
                ErrorCode::NotFound,
                "the enrollment has expired; start again",
            ));
        };
        let Some(step) = totp::verify(&pending.secret, &p.code, now, None) else {
            pending.attempts = pending.attempts.saturating_add(1);
            if pending.attempts < SECOND_FACTOR_ATTEMPTS {
                let expires_at = pending.expires_at;
                self.inner.enrollments.restore(
                    p.enrollment,
                    Some(&user_owner(uid)),
                    pending,
                    expires_at,
                    now,
                );
            }
            return Err(ApiError::invalid_credentials());
        };
        let key = self.key()?;
        let sealed = key.encrypt(&totp_purpose(uid), &pending.secret)?;
        let (codes, stored) = recovery::generate();
        self.inner
            .users
            .update(uid, username, |record| {
                ensure!(record.totp.is_none(), SecondFactorError::AlreadyEnrolled);
                record.totp = Some(TotpRecord {
                    secret: sealed,
                    enrolled_at: now,
                    last_step: Some(step),
                    extra: crate::auth::store::Extra::new(),
                });
                record.recovery_codes = stored;
                Ok(())
            })
            .map_err(second_factor_error)?;
        eprintln!("`{username}` enrolled TOTP");
        Ok(json!({ "recovery_codes": codes }))
    }

    /// Verify the caller's current second factor and apply `change` to the
    /// record in the same locked update.
    fn with_second_factor<R>(
        &self,
        caller: &Caller,
        p: &CodeParams,
        change: impl FnOnce(&mut UserRecord) -> R,
    ) -> Result<R, ApiError> {
        let (uid, username) = caller.user()?;
        let result = self.inner.users.update(uid, username, |record| {
            ensure!(record.totp.is_some(), SecondFactorError::NotEnrolled);
            match self.verify_second_factor(
                record,
                p.code.as_deref(),
                p.recovery_code.as_deref(),
            )? {
                Some(_) => Ok(Some(change(record))),
                None => Ok(None),
            }
        });
        match result {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(ApiError::invalid_credentials()),
            Err(error) => Err(second_factor_error(error)),
        }
    }

    pub(super) fn totp_disable(&self, caller: &Caller, p: &CodeParams) -> ApiResult {
        self.with_second_factor(caller, p, |record| {
            record.totp = None;
            record.recovery_codes.clear();
        })?;
        Ok(json!({ "totp_enrolled": false }))
    }

    pub(super) fn recovery_regenerate(&self, caller: &Caller, p: &CodeParams) -> ApiResult {
        let (codes, stored) = recovery::generate();
        self.with_second_factor(caller, p, |record| record.recovery_codes = stored)?;
        Ok(json!({ "recovery_codes": codes }))
    }

    // --- Passkey registration -------------------------------------------

    pub(super) fn passkey_register_begin(
        &self,
        caller: &Caller,
        p: PasskeyNameParams,
    ) -> ApiResult {
        let webauthn = self.webauthn()?;
        let (uid, username) = caller.user()?;
        self.require_recent_login(caller)?;
        let (handle, exclude) = self.inner.users.update(uid, username, |record| {
            let handle = *record.webauthn_id.get_or_insert_with(|| {
                let mut bytes = [0_u8; 16];
                rand::fill(&mut bytes);
                Uuid::from_bytes(bytes)
            });
            let exclude: Vec<_> = record
                .passkeys
                .iter()
                .map(|stored| stored.passkey.cred_id().clone())
                .collect();
            Ok((handle, exclude))
        })?;
        let (options, state) = webauthn
            .start_passkey_registration(handle, username, username, Some(exclude))
            .map_err(|error| anyhow::anyhow!("webauthn: {error}"))?;
        // webauthn-rs asks for a non-discoverable credential. Prefer a
        // discoverable one so usernameless login (and autofill) works, while
        // keys that cannot store one still register; webauthn-rs does not
        // check this setting when it verifies the result.
        let mut options = json_value(&options);
        options["publicKey"]["authenticatorSelection"]["residentKey"] = json_value(&"preferred");
        let name = passkey_name(p.name)?;
        let now = self.now();
        let expires_at = now.saturating_add(CEREMONY_TTL);
        let ceremony = self
            .inner
            .registrations
            .insert(
                Some(&user_owner(uid)),
                Registration {
                    client: caller.client,
                    uid,
                    username: username.to_owned(),
                    name,
                    state,
                },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(CEREMONY_TTL))?;
        Ok(json!({ "ceremony": ceremony, "options": options, "expires_at": expires_at }))
    }

    pub(super) fn passkey_register_finish(
        &self,
        caller: &Caller,
        p: PasskeyRegisterParams,
    ) -> ApiResult {
        let webauthn = self.webauthn()?;
        let (uid, username) = caller.user()?;
        let now = self.now();
        let Some(registration) = self
            .inner
            .registrations
            .take(&p.ceremony, now)
            .filter(|r| r.uid == uid && r.client == caller.client && r.username == username)
        else {
            return Err(ApiError::new(
                ErrorCode::NotFound,
                "the registration has expired; start again",
            ));
        };
        let passkey = webauthn
            .finish_passkey_registration(&p.credential, &registration.state)
            .map_err(|error| {
                eprintln!("passkey registration failed: {error}");
                ApiError::invalid_credentials()
            })?;
        let id = passkey::credential_id(&passkey);
        let name = match p.name {
            Some(name) => passkey_name(Some(name))?,
            None => registration.name,
        };
        let added = self.inner.users.update(uid, username, |record| {
            // A credential must belong to exactly one account. Checked under
            // the store lock, so two registrations cannot both pass.
            let users = self.inner.users.all()?;
            if users
                .iter()
                .any(|record| record.passkeys.iter().any(|stored| stored.id == id))
            {
                return Ok(false);
            }
            record.passkeys.push(PasskeyRecord {
                id: id.clone(),
                name: name.clone(),
                created_at: now,
                last_used_at: None,
                passkey,
                extra: crate::auth::store::Extra::new(),
            });
            Ok(true)
        })?;
        if !added {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "this passkey is already registered",
            ));
        }
        eprintln!("`{username}` registered a passkey");
        Ok(json!({ "id": id, "name": name, "created_at": now }))
    }

    pub(super) fn passkey_list(&self, caller: &Caller) -> ApiResult {
        let (uid, username) = caller.user()?;
        let passkeys: Vec<Value> = self
            .record(uid, username)?
            .map(|record| record.passkeys)
            .unwrap_or_default()
            .iter()
            .map(|stored| json!({ "id": stored.id, "name": stored.name, "created_at": stored.created_at, "last_used_at": stored.last_used_at }))
            .collect();
        Ok(json!({ "passkeys": passkeys }))
    }

    pub(super) fn passkey_remove(&self, caller: &Caller, p: &PasskeyIdParams) -> ApiResult {
        let (uid, username) = caller.user()?;
        self.require_recent_login(caller)?;
        let removed = self.inner.users.update(uid, username, |record| {
            let before = record.passkeys.len();
            record.passkeys.retain(|stored| stored.id != p.id);
            Ok(before != record.passkeys.len())
        })?;
        if !removed {
            return Err(ApiError::new(ErrorCode::NotFound, "no such passkey"));
        }
        Ok(json!({ "removed": p.id }))
    }
}

/// Reset `username`'s second factor.
///
/// Removes TOTP and recovery codes, and passkeys when `passkeys` is set.
/// Every session of the user is invalidated. Used by
/// the root-only `tetra auth reset-2fa` console command; works without the
/// store key, so it also recovers from a lost TPM.
///
/// # Errors
/// Fails when the account does not exist or the record cannot be written.
pub fn reset_second_factor(
    state_dir: &Path,
    accounts: &dyn AccountSource,
    username: &str,
    passkeys: bool,
) -> Result<Value> {
    let account = accounts
        .by_name(username)?
        .with_context(|| format!("no account named `{username}`"))?;
    let users = UserStore::new(state_dir.join("auth").join("users"));
    users.update(account.uid, &account.name, |record| {
        let had_totp = record.totp.take().is_some();
        let recovery_codes = std::mem::take(&mut record.recovery_codes).len();
        record.second_factor_failures = 0;
        record.second_factor_retry_at = 0;
        let removed_passkeys = if passkeys {
            std::mem::take(&mut record.passkeys).len()
        } else {
            0
        };
        record.session_epoch = record.session_epoch.saturating_add(1);
        Ok(json!({
            "username": account.name,
            "totp_removed": had_totp,
            "recovery_codes_removed": recovery_codes,
            "passkeys_removed": removed_passkeys,
            "sessions_invalidated": true,
        }))
    })
}

fn passkey_name(name: Option<String>) -> Result<String, ApiError> {
    let name = name.unwrap_or_else(|| "Passkey".to_owned());
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_PASSKEY_NAME
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(format!(
            "passkey names must be 1 to {MAX_PASSKEY_NAME} printable characters"
        )));
    }
    Ok(name.to_owned())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CodeParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyNameParams {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyRegisterParams {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyIdParams {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TotpConfirmParams {
    enrollment: String,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionIdParams {
    id: String,
}
