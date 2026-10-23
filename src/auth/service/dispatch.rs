//! Module actions: `module.dispatch`.

use std::sync::Arc;

use crate::{
    agent::{AgentCommand, queue::QueueError},
    auth::{
        api::{ApiError, ApiResult, ErrorCode},
        authz::{self, Principal},
    },
    prelude::*,
};

use super::{AuthService, Caller, blocking};

impl AuthService {
    // --- Module actions --------------------------------------------------

    /// The setup session's rules for `module.dispatch` beyond the
    /// authorization table: [`authz::SETUP_ONLY_WITHOUT_ADMIN`] actions only
    /// while no administrator exists, and [`authz::SETUP_OWN_ACCOUNTS_ONLY`]
    /// actions only on an account the session created (never `root`).
    /// Returns the account a `users.create` (not a dry run) is about to make,
    /// which the session may then set up. `None` for other callers.
    fn setup_dispatch_guard(
        &self,
        caller: &Caller,
        p: &DispatchParams,
    ) -> Result<Option<String>, ApiError> {
        if caller.principal != Principal::Setup {
            return Ok(None);
        }
        let (module, action) = (p.module.as_str(), p.action.as_str());
        let name = p.payload.get("name").and_then(Value::as_str);
        if authz::SETUP_ONLY_WITHOUT_ADMIN.contains(&(module, action)) && self.admin_exists()? {
            return Err(ApiError::forbidden(format!(
                "an administrator already exists, so the setup session may not run {module}.{action}"
            )));
        }
        if authz::SETUP_OWN_ACCOUNTS_ONLY.contains(&(module, action)) {
            let name = name.unwrap_or_default();
            let root = name == "root"
                || self
                    .inner
                    .accounts
                    .by_name(name)?
                    .is_some_and(|account| account.uid == 0);
            if root || !caller.session.created_accounts.iter().any(|c| c == name) {
                return Err(ApiError::forbidden(format!(
                    "the setup session may only run {module}.{action} on accounts it created, never root"
                )));
            }
        }
        let dry_run = p
            .payload
            .get("dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if (module, action) == ("users", "create") && !dry_run {
            Ok(name.map(str::to_owned))
        } else {
            Ok(None)
        }
    }

    /// Run `p` through the dispatch queue for `caller`. The checks before
    /// and the bookkeeping after it read and write the stores, so they run
    /// on the blocking pool; no store lock is held while waiting.
    pub(super) async fn dispatch(
        &self,
        caller: Arc<Caller>,
        id: &str,
        p: DispatchParams,
    ) -> ApiResult {
        caller.authorize(&p.module, &p.action)?;
        let _promotion = if caller.principal == Principal::Setup
            && authz::SETUP_ONLY_WITHOUT_ADMIN.contains(&(p.module.as_str(), p.action.as_str()))
        {
            Some(self.inner.setup_promotion.lock().await)
        } else {
            None
        };
        // Accounts the setup session creates are the ones it may then set up.
        let (p, created) = {
            let (this, caller) = (self.clone(), Arc::clone(&caller));
            blocking(move || {
                let created = this.setup_dispatch_guard(&caller, &p);
                (p, created)
            })
            .await?
        };
        let created = created?;
        if let Some((field, requirement)) =
            authz::unmet_field(&caller.principal, &p.module, &p.payload)
        {
            return Err(ApiError::forbidden(match requirement {
                authz::Requirement::Page(page, level) => format!(
                    "`{field}` on {}.{} needs {} {level:?} access",
                    p.module,
                    p.action,
                    page.label()
                ),
                _ => format!(
                    "only administrators may set `{field}` on {}.{}",
                    p.module, p.action
                ),
            }));
        }
        let user = match &caller.principal {
            Principal::User { username, .. } => Some(username.clone()),
            _ => None,
        };
        let DispatchParams {
            module,
            action,
            payload,
        } = p;
        let command = AgentCommand {
            id: id.to_owned(),
            module: module.clone(),
            action: action.clone(),
            payload,
            signature: None,
            user,
        };
        let response = match self.inner.queue.dispatch(command).await {
            Ok(response) => response,
            Err(QueueError::Full) => {
                return Err(ApiError::new(
                    ErrorCode::QueueFull,
                    "Tetra command queue is full; retry after backoff",
                ));
            }
            Err(QueueError::Closed) => {
                return Err(anyhow::anyhow!("dispatch queue closed").into());
            }
        };
        let this = self.clone();
        let id = id.to_owned();
        blocking(move || -> ApiResult {
            this.record_action(
                &caller,
                &id,
                &module,
                &action,
                response.error.as_deref().map_or(Ok(()), Err),
            );
            if response.ok
                && let Some(name) = created
            {
                this.record_setup_account(&caller.session.id, &name)?;
            }
            if response.ok {
                Ok(response.payload.unwrap_or(Value::Null))
            } else {
                Err(ApiError::new(
                    ErrorCode::ActionFailed,
                    response.error.unwrap_or_default(),
                ))
            }
        })
        .await?
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispatchParams {
    module: String,
    action: String,
    #[serde(default)]
    payload: Value,
}
