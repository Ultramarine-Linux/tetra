//! The launcher: `launcher.*`.

use crate::{
    auth::{
        api::{ApiError, ApiResult, ErrorCode},
        launcher::{ChangeError, EntryInput, Viewer},
        sessions::ClientKind,
    },
    prelude::*,
};

use super::{AuthService, Caller, require_client};

impl AuthService {
    // --- Launcher --------------------------------------------------------

    pub(super) fn launcher_list(&self, caller: &Caller) -> ApiResult {
        let viewer = caller.viewer("list")?;
        let access = self.access();
        let entries: Vec<Value> = self
            .inner
            .launcher
            .visible(&viewer)?
            .iter()
            .map(|entry| entry.to_json(viewer.admin, access.as_ref()))
            .collect();
        Ok(jsonf! { entries })
    }

    pub(super) fn launcher_get(&self, caller: &Caller, p: &LauncherIdParams) -> ApiResult {
        let viewer = caller.viewer("get")?;
        // Hidden entries are `not_found` too, so callers cannot tell them
        // from missing ones.
        let entry = self
            .inner
            .launcher
            .get(&p.id, &viewer)?
            .ok_or_else(launcher_not_found)?;
        Ok(jsonf! { "entry": entry.to_json(viewer.admin, self.access().as_ref()) })
    }

    pub(super) fn launcher_set(&self, caller: &Caller, p: LauncherSetParams) -> ApiResult {
        caller.authorize("launcher", "set")?;
        let access = self.access();
        let entry = self
            .inner
            .launcher
            .set(p.id.as_deref(), p.entry, access.as_ref())?
            .map_err(launcher_change_error)?;
        Ok(jsonf! { "entry": entry.to_json(true, access.as_ref()) })
    }

    pub(super) fn launcher_remove(&self, caller: &Caller, p: &LauncherIdParams) -> ApiResult {
        caller.authorize("launcher", "remove")?;
        self.inner
            .launcher
            .remove(&p.id, self.access().as_ref())?
            .map_err(launcher_change_error)?;
        Ok(jsonf! { "removed": p.id })
    }

    fn launcher_public_json(&self) -> ApiResult {
        Ok(jsonf! {
            "enabled": self.inner.launcher.load()?.public_page,
            "path": self.inner.launcher.public_page_path(),
        })
    }

    pub(super) fn launcher_public_get(&self, caller: &Caller) -> ApiResult {
        caller.authorize("launcher", "public_get")?;
        self.launcher_public_json()
    }

    pub(super) fn launcher_public_set(
        &self,
        caller: &Caller,
        p: LauncherPublicParams,
    ) -> ApiResult {
        caller.authorize("launcher", "public_set")?;
        self.inner
            .launcher
            .set_public_page(p.enabled, self.access().as_ref())?;
        self.launcher_public_json()
    }

    /// Whether `uid` may open entry `id`: for the dashboard's OIDC provider
    /// and Caddy `forward_auth`, which may run without the user's session (a
    /// token refresh, for example). Dashboard only; no token. Accounts that
    /// may not log in, unknown entries and hidden entries are all `false`.
    pub(super) fn launcher_can_access(&self, client: ClientKind, p: &CanAccessParams) -> ApiResult {
        require_client(client, ClientKind::Dashboard)?;
        let viewer = match self.inner.accounts.by_uid(p.uid)? {
            Some(account) if self.inner.policy.check(&account).is_ok() => Some(Viewer {
                admin: account.is_admin(),
                username: account.name,
                groups: account.groups,
            }),
            _ => None,
        };
        let allowed = match viewer {
            Some(viewer) => self.inner.launcher.get(&p.id, &viewer)?.is_some(),
            None => false,
        };
        Ok(jsonf! { allowed })
    }
}

fn launcher_not_found() -> ApiError {
    ApiError::new(ErrorCode::NotFound, "no such entry")
}

fn launcher_change_error(error: ChangeError) -> ApiError {
    match error {
        ChangeError::NotFound => launcher_not_found(),
        ChangeError::Invalid(message) => ApiError::bad_request(message),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LauncherIdParams {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LauncherSetParams {
    /// The entry to replace; a new entry is added without one.
    #[serde(default)]
    id: Option<String>,
    entry: EntryInput,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LauncherPublicParams {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CanAccessParams {
    uid: u32,
    id: String,
}
