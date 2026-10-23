//! Administration: `admin.*` (grants, sessions, the action log).

use serde_json::json;

use crate::{
    auth::{
        api::{ApiError, ApiResult, ErrorCode},
        audit::Origin,
        authz::{Level, Page},
    },
    prelude::*,
};

use super::{AuthService, Caller, UidParams};

const DEFAULT_ACTION_LOG_LIMIT: usize = 100;

impl AuthService {
    // --- Administration --------------------------------------------------

    pub(super) fn grants_get(&self, caller: &Caller, p: UidParams) -> ApiResult {
        caller.require_admin()?;
        if let Some(uid) = p.uid {
            return Ok(json!({
                "uid": uid,
                "grants": self.inner.grants.get(uid)?,
                "effective": self.inner.grants.effective(uid)?,
            }));
        }
        Ok(json!({ "grants": self.inner.grants.all()? }))
    }

    pub(super) fn grants_set(&self, caller: &Caller, p: &GrantsSetParams) -> ApiResult {
        caller.require_admin()?;
        let account = self
            .inner
            .accounts
            .by_uid(p.uid)?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "no such account"))?;
        let grants = self
            .inner
            .grants
            .set(account.uid, &p.grants)
            .map_err(ApiError::bad_request)?;
        eprintln!("updated grants for `{}`", account.name);
        Ok(
            json!({ "uid": account.uid, "grants": grants, "effective": self.inner.grants.effective(account.uid)? }),
        )
    }

    pub(super) fn admin_sessions_revoke(&self, caller: &Caller, p: RequiredUidParams) -> ApiResult {
        caller.require_admin()?;
        let account = self
            .inner
            .accounts
            .by_uid(p.uid)?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "no such account"))?;
        self.inner
            .users
            .update(account.uid, &account.name, |record| {
                record.session_epoch = record.session_epoch.saturating_add(1);
                Ok(())
            })?;
        let revoked = self
            .inner
            .sessions
            .revoke(|session| session.uid == Some(p.uid))?;
        Ok(json!({ "revoked": revoked }))
    }

    pub(super) fn admin_actions(&self, caller: &Caller, p: ActionsParams) -> ApiResult {
        caller.require_admin()?;
        let actions = self
            .inner
            .audit
            .recent(p.limit.unwrap_or(DEFAULT_ACTION_LOG_LIMIT), p.origin)?;
        Ok(json!({ "actions": actions }))
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequiredUidParams {
    uid: u32,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionsParams {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    origin: Option<Origin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantsSetParams {
    uid: u32,
    /// `{page: "view" | "manage" | null}`; `null` removes the grant.
    grants: BTreeMap<Page, Option<Level>>,
}
