//! [`AuthService`]: every operation of the local socket API.
//!
//! The transport ([`crate::agent::local_socket`]) identifies the client from
//! the socket's peer credentials and hands each [`Request`] here together with
//! that [`ClientKind`]. This module authenticates the token, authorizes the
//! operation and runs it. See `docs/auth-protocol.md` for the operations.

use std::{
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use serde_json::json;
use tokio::sync::Semaphore;
use webauthn_rs::prelude::Webauthn;

use crate::{agent::queue::DispatchQueue, prelude::*};

use super::{
    access::AccessConfig,
    accounts::{Account, AccountSource, LoginPolicy},
    api::{ApiError, ApiResult, ErrorCode, Request, Response, params},
    audit::{self, AuditLog, Origin},
    authz::{self, GrantStore, Principal},
    clock::Clock,
    host::HostControl,
    launcher::{LauncherStore, Viewer},
    pam::PasswordBackend,
    passkey::{Authentication, Pending, Registration},
    seal::{Sealer, StoreKey},
    sessions::{
        AuthMethod, ClientKind, NewSession, Session, SessionError, SessionKind, SessionStore,
    },
    setup::{AddressThrottle, Setup},
    shell::ShellTicket,
    users::{UserRecord, UserStore},
};

mod access_ops;
mod account;
mod admin;
mod config;
mod dispatch;
mod launcher_ops;
mod login;
mod oobe;
mod shell_ops;

pub use account::reset_second_factor;
pub use config::AuthConfig;
pub use oobe::Handoff;

/// Wrong second-factor codes allowed per password login.
const SECOND_FACTOR_ATTEMPTS: u32 = 5;
/// Concurrent PAM transactions.
const PAM_CONCURRENCY: usize = 4;
/// Operations that change the host or who may do what, recorded in the
/// action log (with the request's id) whether they succeed or fail.
const AUDITED_OPERATIONS: &[&str] = &[
    "access.set",
    "setup.complete",
    "admin.grants_set",
    "admin.sessions_revoke",
    "launcher.set",
    "launcher.remove",
    "launcher.public_set",
];
/// Root-only state: credentials, grants, sessions, the setup marker.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/tetra";
/// terra-caddy's drop-in directory, imported by its default Caddyfile as
/// `import Caddyfile.d/*.caddyfile`.
pub const CADDY_SITES_DIR: &str = "/etc/caddy/Caddyfile.d";
/// Seconds between `setup.complete` answering and the OOBE being stopped, so
/// it can show its final screen.
pub const HANDOFF_SECONDS: u32 = 5;
/// Seconds after logging in during which a session may add or remove a way
/// to log in (TOTP, passkeys). A stolen session older than this cannot
/// plant a credential that would outlive it.
pub const REAUTH_WINDOW: i64 = 600;
/// The dashboard's unit, generated from its Quadlet.
pub const DASHBOARD_UNIT: &str = "ultramarine-dashboard.service";
/// The server OOBE's unit.
pub const OOBE_UNIT: &str = "ultramarine-server-oobe.service";
/// The boot unit that publishes the setup code.
pub const SETUP_CODE_UNIT: &str = "tetra-setup-code.service";
#[cfg(feature = "reverse-proxy")]
const CADDY_UNIT: &str = "caddy.service";

/// The host-facing dependencies, swapped for fakes in tests.
pub struct Backends {
    pub accounts: Arc<dyn AccountSource>,
    pub passwords: Arc<dyn PasswordBackend>,
    pub sealer: Arc<dyn Sealer>,
    pub clock: Arc<dyn Clock>,
    pub policy: LoginPolicy,
    /// systemctl and systemd-run.
    pub host: Arc<dyn HostControl>,
}

struct PendingLogin {
    client: ClientKind,
    uid: u32,
    username: String,
    attempts: u32,
    expires_at: i64,
}

struct PendingTotp {
    client: ClientKind,
    uid: u32,
    secret: Vec<u8>,
    attempts: u32,
    expires_at: i64,
}

struct Inner {
    config: AuthConfig,
    accounts: Arc<dyn AccountSource>,
    passwords: Arc<dyn PasswordBackend>,
    sealer: Arc<dyn Sealer>,
    clock: Arc<dyn Clock>,
    policy: LoginPolicy,
    host: Arc<dyn HostControl>,
    queue: DispatchQueue,
    users: UserStore,
    grants: GrantStore,
    launcher: LauncherStore,
    sessions: SessionStore,
    setup: Setup,
    redeem_throttle: AddressThrottle,
    /// Held from the "no administrator yet" check through the dispatch of a
    /// [`authz::SETUP_ONLY_WITHOUT_ADMIN`] action, so two concurrent
    /// requests cannot both pass the check.
    setup_promotion: tokio::sync::Mutex<()>,
    /// Held for a whole `access.set`, which reads what the previous one wrote.
    access_lock: Mutex<()>,
    audit: AuditLog,
    key: Mutex<Option<Arc<StoreKey>>>,
    webauthn: RwLock<Option<Arc<Webauthn>>>,
    logins: Pending<PendingLogin>,
    enrollments: Pending<PendingTotp>,
    registrations: Pending<Registration>,
    authentications: Pending<Authentication>,
    shell_tickets: Pending<ShellTicket>,
    pam: Semaphore,
}

/// The authenticated caller of an operation.
struct Caller {
    client: ClientKind,
    session: Session,
    principal: Principal,
    /// The user's groups, for launcher visibility. Empty for other
    /// principals.
    groups: Vec<String>,
}

impl Caller {
    fn user(&self) -> Result<(u32, &str), ApiError> {
        match &self.principal {
            Principal::User { uid, username, .. } => Ok((*uid, username)),
            _ => Err(ApiError::forbidden("this operation needs a logged-in user")),
        }
    }

    const fn is_admin(&self) -> bool {
        matches!(self.principal, Principal::User { admin: true, .. })
    }

    fn require_admin(&self) -> Result<(), ApiError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(ApiError::forbidden("this operation needs an administrator"))
        }
    }

    /// Check `module.action` against the authorization table.
    fn authorize(&self, module: &str, action: &str) -> Result<(), ApiError> {
        if self.principal.allows(module, action) {
            return Ok(());
        }
        let reason = match (&self.principal, authz::requirement(module, action)) {
            (Principal::Setup, _) => "the setup session may only run OOBE operations".to_owned(),
            (_, authz::Requirement::Page(page, level)) => format!(
                "{module}.{action} needs {} permission on {}",
                json_value(&level).as_str().unwrap_or_default(),
                json_value(&page).as_str().unwrap_or_default()
            ),
            _ => format!("{module}.{action} is limited to administrators"),
        };
        Err(ApiError::forbidden(reason))
    }

    /// The caller as a launcher viewer, after checking `launcher.action`.
    fn viewer(&self, action: &str) -> Result<Viewer, ApiError> {
        self.authorize("launcher", action)?;
        let (_, username) = self.user()?;
        Ok(Viewer {
            username: username.to_owned(),
            groups: self.groups.clone(),
            admin: self.is_admin(),
        })
    }

    fn require_setup_or_admin(&self) -> Result<(), ApiError> {
        if self.is_admin() || self.principal == Principal::Setup {
            Ok(())
        } else {
            Err(ApiError::forbidden(
                "this operation needs the setup session or an administrator",
            ))
        }
    }
}

/// Where [`AuthService::route_sync`] leaves a request.
enum Routed {
    /// Answered.
    Done(Value),
    /// An authenticated `module.dispatch`, which waits for the dispatch
    /// queue.
    Dispatch(Arc<Caller>),
}

/// Login and authorization authority. Cheap to clone.
#[derive(Clone)]
pub struct AuthService {
    inner: Arc<Inner>,
}

fn require_client(client: ClientKind, expected: ClientKind) -> Result<(), ApiError> {
    if client == expected {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::WrongClient,
            format!("only the {} may use this operation", client_name(expected)),
        ))
    }
}

const fn client_name(client: ClientKind) -> &'static str {
    match client {
        ClientKind::Dashboard => "dashboard",
        ClientKind::Oobe => "OOBE",
    }
}

/// Owner of pending state that belongs to a user, for
/// [`passkey::Pending`](super::passkey::Pending).
fn user_owner(uid: u32) -> String {
    format!("uid:{uid}")
}

fn totp_purpose(uid: u32) -> String {
    format!("totp-secret:{uid}")
}

fn passkeys_unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::PasskeysUnavailable,
        "passkeys need the dashboard to be reached through a domain name; this server is in IP mode or has no access configuration",
    )
}

fn session_json(session: &Session, current: Option<&Session>) -> Value {
    json!({
        "id": session.id, "client": session.client, "kind": session.kind, "method": session.method, "uid": session.uid,
        "username": session.username, "created_at": session.created_at, "expires_at": session.expires_at, "last_seen": session.last_seen,
        "current": current.is_some_and(|current| current.id == session.id),
    })
}

impl AuthService {
    /// Load stored state and the access configuration.
    ///
    /// # Errors
    /// Fails when the state directory or stored sessions cannot be read.
    pub fn new(config: AuthConfig, backends: Backends, queue: DispatchQueue) -> Result<Self> {
        let auth_dir = config.auth_dir();
        super::store::private_dir(&config.state_dir)?;
        super::store::private_dir(&auth_dir)?;
        // pam_faillock records dashboard failures here (see the PAM file).
        super::store::private_dir(&config.state_dir.join(super::pam::FAILLOCK_DIR))?;
        let now = backends.clock.now();
        let sessions =
            SessionStore::load(auth_dir.join("sessions.json"), config.session_policy, now)?;
        let access = AccessConfig::load(&config.access_path()).unwrap_or_else(|error| {
            eprintln!("ignoring the access configuration: {error:#}");
            None
        });
        let webauthn = access
            .as_ref()
            .map(AccessConfig::webauthn)
            .transpose()
            .unwrap_or_else(|error| {
                eprintln!("passkeys disabled: {error:#}");
                None
            })
            .flatten()
            .map(Arc::new);
        let launcher = LauncherStore::new(config.launcher_path(), config.public_dir.clone());
        // Bring the public page in line with the stored entries, for example
        // after a rollback or a manual edit.
        if let Err(error) = launcher.refresh_public_page(access.as_ref()) {
            eprintln!("failed to write the launcher's public page: {error:#}");
        }
        Ok(Self {
            inner: Arc::new(Inner {
                users: UserStore::new(auth_dir.join("users")),
                grants: GrantStore::new(auth_dir.join("grants.json")),
                launcher,
                setup: Setup::new(config.setup_paths()),
                redeem_throttle: AddressThrottle::default(),
                setup_promotion: tokio::sync::Mutex::new(()),
                access_lock: Mutex::new(()),
                audit: AuditLog::new(config.state_dir.join("audit")),
                sessions,
                accounts: backends.accounts,
                passwords: backends.passwords,
                sealer: backends.sealer,
                clock: backends.clock,
                policy: backends.policy,
                host: backends.host,
                queue,
                config,
                key: Mutex::new(None),
                webauthn: RwLock::new(webauthn),
                logins: Pending::default(),
                enrollments: Pending::default(),
                registrations: Pending::default(),
                authentications: Pending::default(),
                shell_tickets: Pending::default(),
                pam: Semaphore::new(PAM_CONCURRENCY),
            }),
        })
    }

    /// The action log, shared with the remote-control transport.
    #[must_use]
    pub fn audit(&self) -> AuditLog {
        self.inner.audit.clone()
    }

    /// Refuse to change how the caller logs in unless their session is
    /// younger than [`REAUTH_WINDOW`].
    fn require_recent_login(&self, caller: &Caller) -> Result<(), ApiError> {
        if self.now().saturating_sub(caller.session.created_at) <= REAUTH_WINDOW {
            Ok(())
        } else {
            Err(ApiError::new(
                ErrorCode::ReauthRequired,
                "log in again to change how you log in",
            ))
        }
    }

    fn now(&self) -> i64 {
        self.inner.clock.now()
    }

    /// Facts for the `hello` frame, read on the blocking pool (the setup
    /// marker is a file).
    ///
    /// # Errors
    /// Fails only when the blocking task panics.
    pub async fn hello(&self) -> Result<Value> {
        let this = self.clone();
        Ok(tokio::task::spawn_blocking(move || this.hello_facts()).await?)
    }

    /// Facts for the `hello` frame.
    fn hello_facts(&self) -> Value {
        json!({
            "setup_required": !self.inner.setup.is_complete(),
            "passkeys_available": self.webauthn().is_ok(),
        })
    }

    /// Write session `last_seen` updates every `interval`, forever.
    #[expect(
        clippy::infinite_loop,
        reason = "runs for the daemon's lifetime; the caller selects on it"
    )]
    pub async fn flush_sessions_every(&self, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            // Writes and syncs the session file, so off the async workers.
            let this = self.clone();
            let flushed = tokio::task::spawn_blocking(move || this.flush_sessions()).await;
            match flushed {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("failed to save sessions: {error:#}"),
                Err(error) => eprintln!("failed to save sessions: {error}"),
            }
        }
    }

    /// Write pending session updates now (for shutdown).
    ///
    /// # Errors
    /// Fails when the session file cannot be written.
    pub fn flush_sessions(&self) -> Result<()> {
        self.inner.sessions.flush(self.now())
    }

    /// Run one request from `client`.
    pub async fn handle(&self, client: ClientKind, request: Request) -> Response {
        let request = Arc::new(request);
        let result = self.route(client, &request).await;
        Response::new(request.id.clone(), result)
    }

    /// Run `request`. Logins wait for PAM and `module.dispatch` for the
    /// dispatch queue here; everything else reads and writes the stores, so
    /// it runs in one [`blocking`] call ([`Self::route_sync`]).
    async fn route(&self, client: ClientKind, request: &Arc<Request>) -> ApiResult {
        let p = &request.params;
        match request.op.as_str() {
            "auth.password" => return self.auth_password(client, params(p)?).await,
            "auth.passkey_finish" => return self.auth_passkey_finish(client, params(p)?).await,
            // Turns a connection into a shell stream, so the transport
            // handles it, and only as a connection's first request.
            "shell.open" => {
                return Err(ApiError::bad_request(
                    "shell.open must be the first request on a new connection",
                ));
            }
            _ => {}
        }
        let this = self.clone();
        let shared = Arc::clone(request);
        match blocking(move || this.route_sync(client, &shared)).await?? {
            Routed::Done(value) => Ok(value),
            // Module actions are recorded by `dispatch`, with their own
            // outcome.
            Routed::Dispatch(caller) => self.dispatch(caller, &request.id, params(p)?).await,
        }
    }

    /// The synchronous part of [`Self::route`]: authenticate, authorize and
    /// run every operation but the logins that need PAM, and record the
    /// [`AUDITED_OPERATIONS`] before answering. `module.dispatch` comes back
    /// authenticated, for `route` to queue.
    fn route_sync(&self, client: ClientKind, request: &Request) -> Result<Routed, ApiError> {
        let p = &request.params;
        let unauthenticated = match request.op.as_str() {
            "auth.second_factor" => Some(self.auth_second_factor(client, params(p)?)),
            "auth.passkey_begin" => Some(self.auth_passkey_begin(client, &params(p)?)),
            "setup.status" => Some(self.setup_status(client, request.token.as_deref())),
            "setup.redeem" => Some(self.setup_redeem(client, &params(p)?)),
            "launcher.can_access" => Some(self.launcher_can_access(client, &params(p)?)),
            _ => None,
        };
        if let Some(result) = unauthenticated {
            return result.map(Routed::Done);
        }
        let caller = self.authenticate(client, request.token.as_deref())?;
        if caller.principal == Principal::Setup && !authz::setup_allows_operation(&request.op) {
            return Err(ApiError::forbidden(format!(
                "the setup session may not use `{}`",
                request.op
            )));
        }
        let result = match request.op.as_str() {
            "session.info" => Ok(Self::session_info(&caller)),
            "session.logout" => self.session_logout(&caller),
            "session.list" => self.session_list(&caller, params(p)?),
            "session.revoke" => self.session_revoke(&caller, &params(p)?),
            "account.status" => self.account_status(&caller),
            "account.totp_begin" => self.totp_begin(&caller),
            "account.totp_confirm" => self.totp_confirm(&caller, params(p)?),
            "account.totp_disable" => self.totp_disable(&caller, &params(p)?),
            "account.recovery_regenerate" => self.recovery_regenerate(&caller, &params(p)?),
            "account.passkey_register_begin" => self.passkey_register_begin(&caller, params(p)?),
            "account.passkey_register_finish" => self.passkey_register_finish(&caller, params(p)?),
            "account.passkey_list" => self.passkey_list(&caller),
            "account.passkey_remove" => self.passkey_remove(&caller, &params(p)?),
            "authz.catalog" => Ok(authz::catalog()),
            "admin.grants_get" => self.grants_get(&caller, params(p)?),
            "admin.grants_set" => self.grants_set(&caller, &params(p)?),
            "admin.sessions_revoke" => self.admin_sessions_revoke(&caller, params(p)?),
            "admin.actions" => self.admin_actions(&caller, params(p)?),
            "launcher.list" => self.launcher_list(&caller),
            "launcher.get" => self.launcher_get(&caller, &params(p)?),
            "launcher.set" => self.launcher_set(&caller, params(p)?),
            "launcher.remove" => self.launcher_remove(&caller, &params(p)?),
            "launcher.public_get" => self.launcher_public_get(&caller),
            "launcher.public_set" => self.launcher_public_set(&caller, params(p)?),
            "access.get" => self.access_get(),
            "access.set" => self.access_set(&caller, params(p)?),
            "setup.complete" => self.setup_complete(&caller),
            "module.dispatch" => return Ok(Routed::Dispatch(Arc::new(caller))),
            "shell.ticket" => self.shell_ticket(&caller, params(p)?),
            op => Err(ApiError::new(
                ErrorCode::UnknownOperation,
                format!("unknown operation `{op}`"),
            )),
        };
        // Requests refused before anything changed are not recorded.
        let refused = matches!(
            &result,
            Err(ApiError {
                code: ErrorCode::BadRequest | ErrorCode::Forbidden,
                ..
            })
        );
        if !refused
            && AUDITED_OPERATIONS.contains(&request.op.as_str())
            && let Some((module, action)) = request.op.split_once('.')
        {
            let outcome = result
                .as_ref()
                .map(drop)
                .map_err(|error| error.message.as_str());
            self.record_action(&caller, &request.id, module, action, outcome);
        }
        result.map(Routed::Done)
    }

    // --- Accounts and sessions ------------------------------------------

    /// The account `name`, if it exists and may log in.
    fn eligible_by_name(&self, name: &str) -> Result<Option<Account>, ApiError> {
        Ok(self.eligible(self.inner.accounts.by_name(name)?))
    }

    /// The account `uid`, if it still has the name `username` and may log in.
    fn eligible_by_uid(&self, uid: u32, username: &str) -> Result<Option<Account>, ApiError> {
        Ok(self.eligible(
            self.inner
                .accounts
                .by_uid(uid)?
                .filter(|account| account.name == username),
        ))
    }

    /// `account`, if the login policy lets it log in.
    fn eligible(&self, account: Option<Account>) -> Option<Account> {
        let account = account?;
        match self.inner.policy.check(&account) {
            Ok(()) => Some(account),
            Err(reason) => {
                eprintln!("refusing `{}`: {reason}", account.name);
                None
            }
        }
    }

    fn record(&self, uid: u32, username: &str) -> Result<Option<UserRecord>, ApiError> {
        Ok(self.inner.users.get(uid, username)?)
    }

    fn issue_user_session(
        &self,
        client: ClientKind,
        account: &Account,
        method: AuthMethod,
    ) -> ApiResult {
        let epoch = self
            .record(account.uid, &account.name)?
            .map_or(0, |record| record.session_epoch);
        let (token, session) = self.inner.sessions.issue(
            NewSession {
                uid: Some(account.uid),
                username: Some(account.name.clone()),
                client,
                kind: SessionKind::User,
                method,
                epoch,
            },
            self.now(),
        )?;
        eprintln!(
            "issued a {} session for `{}` ({method:?})",
            client_name(client),
            account.name
        );
        Ok(json!({
            "status": "authenticated",
            "token": token,
            "session": session_json(&session, None),
            "user": { "uid": account.uid, "username": account.name, "admin": account.is_admin() },
        }))
    }

    fn authenticate(&self, client: ClientKind, token: Option<&str>) -> Result<Caller, ApiError> {
        let token = token.ok_or_else(ApiError::unauthenticated)?;
        let now = self.now();
        let session = self
            .inner
            .sessions
            .validate(token, client, now)
            .map_err(session_error)?;
        let mut groups = Vec::new();
        let principal = match session.kind {
            SessionKind::Setup => {
                if self.inner.setup.is_complete() {
                    return Err(self.revoke_session(&session));
                }
                Principal::Setup
            }
            SessionKind::User => {
                let (principal, account) = self.user_principal(&session)?;
                groups = account.groups;
                principal
            }
        };
        Ok(Caller {
            client,
            session,
            principal,
            groups,
        })
    }

    /// End `session` because it may no longer be used.
    fn revoke_session(&self, session: &Session) -> ApiError {
        let id = session.id.clone();
        self.inner.sessions.revoke(|s| s.id == id).ok();
        ApiError::unauthenticated()
    }

    /// The principal of a user session, after checking that its account
    /// still exists under the same name, may still log in, and has not ended
    /// its sessions since (session epoch). Ends the session otherwise.
    fn user_principal(&self, session: &Session) -> Result<(Principal, Account), ApiError> {
        let (Some(uid), Some(username)) = (session.uid, session.username.clone()) else {
            return Err(self.revoke_session(session));
        };
        // Account state is checked on every request, so locking or
        // deleting an account ends its sessions immediately.
        let Some(account) = self.eligible_by_uid(uid, &username)? else {
            return Err(self.revoke_session(session));
        };
        let epoch = self
            .record(uid, &username)?
            .map_or(0, |record| record.session_epoch);
        if session.epoch != epoch {
            return Err(self.revoke_session(session));
        }
        let admin = account.is_admin();
        let principal = Principal::User {
            uid,
            username,
            admin,
            permissions: if admin {
                authz::Permissions::new()
            } else {
                self.inner.grants.effective(uid)?
            },
        };
        Ok((principal, account))
    }

    // --- Store key, relying party, access configuration -----------------

    fn key(&self) -> Result<Arc<StoreKey>> {
        let mut key = self
            .inner
            .key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(key) = key.as_ref() {
            return Ok(Arc::clone(key));
        }
        // Held while loading, so concurrent first uses create one key.
        let loaded = Arc::new(StoreKey::load_or_create(
            &self.inner.config.store_key_path(),
            self.inner.sealer.as_ref(),
        )?);
        *key = Some(Arc::clone(&loaded));
        drop(key);
        Ok(loaded)
    }

    fn webauthn(&self) -> Result<Arc<Webauthn>, ApiError> {
        self.inner
            .webauthn
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(passkeys_unavailable)
    }

    fn access(&self) -> Option<AccessConfig> {
        AccessConfig::load(&self.inner.config.access_path()).unwrap_or_else(|error| {
            eprintln!("ignoring the access configuration: {error:#}");
            None
        })
    }

    // --- Module actions --------------------------------------------------

    fn record_action(
        &self,
        caller: &Caller,
        command_id: &str,
        module: &str,
        action: &str,
        outcome: Result<(), &str>,
    ) {
        let (origin, uid, username) = match &caller.principal {
            Principal::User { uid, username, .. } => {
                (Origin::Local, Some(*uid), Some(username.clone()))
            }
            Principal::Setup => (Origin::Setup, None, None),
            Principal::RemoteController => (Origin::Remote, None, None),
        };
        self.inner.audit.record(&audit::Entry {
            at: self.now(),
            origin,
            client: Some(caller.client),
            uid,
            username,
            host_id: None,
            command_id: command_id.to_owned(),
            module: module.to_owned(),
            action: action.to_owned(),
            ok: outcome.is_ok(),
            error: outcome.err().map(str::to_owned),
            detail: None,
        });
    }

    /// Record that the setup session `session_id` created the account
    /// `name`, which lets it set that account's password and SSH keys.
    pub(crate) fn record_setup_account(&self, session_id: &str, name: &str) -> Result<()> {
        self.inner.sessions.add_created_account(session_id, name)
    }
}

/// The answer for a session that cannot be used.
fn session_error(error: SessionError) -> ApiError {
    match error {
        SessionError::WrongClient => ApiError::new(
            ErrorCode::WrongClient,
            "this token was issued to the other local client",
        ),
        SessionError::Invalid | SessionError::Expired => ApiError::unauthenticated(),
    }
}

/// Run `work` on the blocking pool.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| anyhow::anyhow!(error).into())
}

/// A failure as reported in a result, for steps that must not stop the
/// operation.
fn error_text<T>(result: Result<T>) -> Option<String> {
    result.err().map(|error| format!("{error:#}"))
}

fn json_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct UidParams {
    #[serde(default)]
    uid: Option<u32>,
}
