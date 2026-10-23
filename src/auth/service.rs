//! [`AuthService`]: every operation of the local socket API.
//!
//! The transport ([`crate::agent::local_socket`]) identifies the client from
//! the socket's peer credentials and hands each [`Request`] here together with
//! that [`ClientKind`]. This module authenticates the token, authorizes the
//! operation and runs it. See `docs/auth-protocol.md` for the operations.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Duration,
};

use tokio::sync::Semaphore;
use webauthn_rs::prelude::{
    DiscoverableKey, Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn,
};

use crate::{
    agent::{AgentCommand, queue::DispatchQueue, queue::QueueError},
    prelude::*,
};

use super::{
    access::{AccessConfig, AccessRequest, AcmeChallenge},
    accounts::{Account, AccountSource, LoginPolicy},
    api::{ApiError, ApiResult, ErrorCode, Request, Response, params},
    audit::{self, AuditLog, Origin},
    authz::{self, GrantStore, Level, Page, Principal},
    clock::Clock,
    dns::{DnsCredentials, StoredDnsCredentials},
    host::HostControl,
    launcher::{ChangeError, EntryInput, LauncherStore, Viewer},
    pam::{PamOutcome, PasswordBackend},
    passkey::{self, Authentication, AuthenticationState, CEREMONY_TTL, Pending, Registration},
    recovery,
    seal::{Sealer, StoreKey},
    secrets::{DNS_CREDENTIALS, SecretStore},
    sessions::{
        AuthMethod, ClientKind, NewSession, Session, SessionError, SessionKind, SessionPolicy,
        SessionStore,
    },
    setup::{AddressThrottle, RedeemError, Setup, SetupPaths},
    store, totp,
    users::{PasskeyRecord, TotpRecord, UserRecord, UserStore},
};

/// Seconds between the password and the second factor.
const LOGIN_TTL: i64 = 300;
/// Wrong second-factor codes allowed per password login.
const SECOND_FACTOR_ATTEMPTS: u32 = 5;
/// Consecutive wrong second-factor codes per account, across logins, before
/// each further attempt has to wait.
const SECOND_FACTOR_FREE_FAILURES: u32 = 10;
/// Longest wait between second-factor attempts per account, in seconds.
const SECOND_FACTOR_MAX_BACKOFF: i64 = 900;
/// Seconds to confirm a TOTP enrollment.
const ENROLLMENT_TTL: i64 = 600;
/// Concurrent PAM transactions.
const PAM_CONCURRENCY: usize = 4;
const MAX_PASSKEY_NAME: usize = 64;
const DEFAULT_ACTION_LOG_LIMIT: usize = 100;
/// The setup-code throttle bucket shared by every `remote_addr` that is not
/// an IP address.
const UNPARSEABLE_ADDRESS: &str = "unparseable";
/// Root-only state: credentials, grants, sessions, the setup marker.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/tetra";
/// terra-caddy's drop-in directory, imported by its default Caddyfile as
/// `import Caddyfile.d/*.caddyfile`.
pub const CADDY_SITES_DIR: &str = "/etc/caddy/Caddyfile.d";
/// Seconds between `setup.complete` answering and the OOBE being stopped, so
/// it can show its final screen.
pub const HANDOFF_SECONDS: u32 = 5;
/// The dashboard's unit, generated from its Quadlet.
pub const DASHBOARD_UNIT: &str = "ultramarine-dashboard.service";
/// The server OOBE's unit.
pub const OOBE_UNIT: &str = "ultramarine-server-oobe.service";
/// The boot unit that publishes the setup code.
pub const SETUP_CODE_UNIT: &str = "tetra-setup-code.service";
#[cfg(feature = "reverse-proxy")]
const CADDY_UNIT: &str = "caddy.service";
/// Transient unit that finishes the handoff.
const HANDOFF_UNIT: &str = "tetra-setup-handoff";
/// `caddy.service` drop-in that loads the DNS-01 environment file.
#[cfg(feature = "reverse-proxy")]
const CADDY_DROP_IN: &str = "caddy.service.d/50-tetra.conf";

/// Filesystem locations.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// `/var/lib/tetra`.
    pub state_dir: PathBuf,
    /// `/run/tetra`.
    pub run_dir: PathBuf,
    /// `/run/issue.d`.
    pub issue_dir: PathBuf,
    /// Caddy site directory (terra-caddy's `/etc/caddy/Caddyfile.d`) for the
    /// dashboard's and the OOBE's sites.
    pub caddy_sites_dir: PathBuf,
    /// DNS-01 credentials for Caddy (`/etc/caddy/tetra-dns.env`).
    pub caddy_env_file: PathBuf,
    /// The root certificate of Caddy's internal CA, whose fingerprint the
    /// console shows during setup.
    pub caddy_root_ca: PathBuf,
    /// Unit drop-ins (`/etc/systemd/system`).
    pub systemd_dir: PathBuf,
    /// The dashboard container's environment (`/etc/ultramarine-dashboard/env`).
    pub dashboard_env_file: PathBuf,
    /// This binary, run by the handoff timer.
    pub tetra_binary: PathBuf,
    /// Dashboard address for the Caddy site when `access.set` does not name
    /// one.
    pub dashboard_upstream: String,
    /// Where the launcher's public page is written, readable by Caddy.
    pub public_dir: PathBuf,
    pub session_policy: SessionPolicy,
}

impl AuthConfig {
    /// Production paths under `state_dir` ([`DEFAULT_STATE_DIR`] unless
    /// moved).
    #[must_use]
    pub fn system(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            run_dir: "/run/tetra".into(),
            issue_dir: "/run/issue.d".into(),
            caddy_sites_dir: CADDY_SITES_DIR.into(),
            caddy_env_file: "/etc/caddy/tetra-dns.env".into(),
            // `caddy.service` runs as `caddy` with HOME=/var/lib/caddy, so
            // its data directory is ~/.local/share/caddy.
            caddy_root_ca: "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt"
                .into(),
            systemd_dir: "/etc/systemd/system".into(),
            dashboard_env_file: "/etc/ultramarine-dashboard/env".into(),
            tetra_binary: "/usr/bin/tetra".into(),
            dashboard_upstream: super::access::DEFAULT_DASHBOARD_UPSTREAM.to_owned(),
            public_dir: super::launcher::DEFAULT_PUBLIC_DIR.into(),
            session_policy: SessionPolicy::default(),
        }
    }

    /// The agent's modules, with the ones that keep files under these
    /// directories (remote access and updates) using these paths.
    #[must_use]
    pub fn dispatcher(&self) -> crate::agent::Dispatcher {
        let dispatcher = crate::agent::Dispatcher::full();
        #[cfg(feature = "updates")]
        let dispatcher = {
            use crate::agent::modules::updates::{Paths, UpdatesModule};
            dispatcher.with_module(UpdatesModule::with_paths(Paths::for_config(self)))
        };
        #[cfg(feature = "remote-access")]
        let dispatcher = {
            use crate::agent::modules::remote_access::{Paths, RemoteAccessModule};
            dispatcher.with_module(RemoteAccessModule::with_paths(Paths::for_config(self)))
        };
        dispatcher
    }

    #[must_use]
    pub fn auth_dir(&self) -> PathBuf {
        self.state_dir.join("auth")
    }

    #[must_use]
    pub fn access_path(&self) -> PathBuf {
        self.state_dir.join("access.json")
    }

    /// Sealed credentials for other services.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.state_dir.join("secrets")
    }

    #[must_use]
    pub fn launcher_path(&self) -> PathBuf {
        self.state_dir.join("launcher.json")
    }

    #[must_use]
    pub fn store_key_path(&self) -> PathBuf {
        self.auth_dir().join("store-key.cred")
    }

    #[must_use]
    pub fn setup_paths(&self) -> SetupPaths {
        SetupPaths {
            state_dir: self.state_dir.clone(),
            auth_dir: self.auth_dir(),
            run_dir: self.run_dir.clone(),
            issue_dir: self.issue_dir.clone(),
        }
    }
}

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
    /// Held for a whole `access.set`, which reads what the previous one wrote.
    access_lock: Mutex<()>,
    audit: AuditLog,
    key: Mutex<Option<Arc<StoreKey>>>,
    webauthn: RwLock<Option<Arc<Webauthn>>>,
    logins: Pending<PendingLogin>,
    enrollments: Pending<PendingTotp>,
    registrations: Pending<Registration>,
    authentications: Pending<Authentication>,
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

/// Owner of pending state that belongs to a user, for [`passkey::Pending`].
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
    jsonf! {
        session.id, session.client, session.kind, session.method, session.uid,
        session.username, session.created_at, session.expires_at, session.last_seen,
        "current": current.is_some_and(|current| current.id == session.id),
    }
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
        let webauthn = match AccessConfig::load(&config.access_path()) {
            Ok(access) => access
                .map(|access| access.webauthn())
                .transpose()
                .unwrap_or_else(|error| {
                    eprintln!("passkeys disabled: {error:#}");
                    None
                })
                .flatten()
                .map(Arc::new),
            Err(error) => {
                eprintln!("passkeys disabled: {error:#}");
                None
            }
        };
        let launcher = LauncherStore::new(config.launcher_path(), config.public_dir.clone());
        // Bring the public page in line with the stored entries, for example
        // after a rollback or a manual edit.
        if let Err(error) = launcher.refresh_public_page(
            AccessConfig::load(&config.access_path())
                .ok()
                .flatten()
                .as_ref(),
        ) {
            eprintln!("failed to write the launcher's public page: {error:#}");
        }
        Ok(Self {
            inner: Arc::new(Inner {
                users: UserStore::new(auth_dir.join("users")),
                grants: GrantStore::new(auth_dir.join("grants.json")),
                launcher,
                setup: Setup::new(config.setup_paths()),
                redeem_throttle: AddressThrottle::default(),
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
                pam: Semaphore::new(PAM_CONCURRENCY),
            }),
        })
    }

    /// The action log, shared with the remote-control transport.
    #[must_use]
    pub fn audit(&self) -> AuditLog {
        self.inner.audit.clone()
    }

    fn now(&self) -> i64 {
        self.inner.clock.now()
    }

    /// Facts for the `hello` frame.
    #[must_use]
    pub fn hello(&self) -> Value {
        jsonf! {
            "setup_required": !self.inner.setup.is_complete(),
            "passkeys_available": self.webauthn().is_ok(),
        }
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
            if let Err(error) = self.inner.sessions.flush(self.now()) {
                eprintln!("failed to save sessions: {error:#}");
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
        let result = self.route(client, &request).await;
        Response::new(request.id, result)
    }

    async fn route(&self, client: ClientKind, request: &Request) -> ApiResult {
        let p = &request.params;
        match request.op.as_str() {
            "auth.password" => return self.auth_password(client, params(p)?).await,
            "auth.second_factor" => return self.auth_second_factor(client, params(p)?),
            "auth.passkey_begin" => return self.auth_passkey_begin(client, &params(p)?),
            "auth.passkey_finish" => return self.auth_passkey_finish(client, params(p)?).await,
            "setup.status" => return self.setup_status(client, request.token.as_deref()),
            "setup.redeem" => return self.setup_redeem(client, &params(p)?),
            "launcher.can_access" => return self.launcher_can_access(client, &params(p)?),
            _ => {}
        }
        let caller = self.authenticate(client, request.token.as_deref())?;
        if caller.principal == Principal::Setup && !authz::setup_allows_operation(&request.op) {
            return Err(ApiError::forbidden(format!(
                "the setup session may not use `{}`",
                request.op
            )));
        }
        match request.op.as_str() {
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
            "access.set" => self.access_set(&caller, params(p)?).await,
            "setup.complete" => self.setup_complete(&caller).await,
            "module.dispatch" => self.dispatch(&caller, &request.id, params(p)?).await,
            op => Err(ApiError::new(
                ErrorCode::UnknownOperation,
                format!("unknown operation `{op}`"),
            )),
        }
    }

    // --- Accounts and sessions ------------------------------------------

    /// The account `name`, if it exists and may log in.
    fn eligible_by_name(&self, name: &str) -> Result<Option<Account>, ApiError> {
        let Some(account) = self.inner.accounts.by_name(name)? else {
            return Ok(None);
        };
        match self.inner.policy.check(&account) {
            Ok(()) => Ok(Some(account)),
            Err(reason) => {
                eprintln!("login refused for `{name}`: {reason}");
                Ok(None)
            }
        }
    }

    /// The account `uid`, if it still has the name `username` and may log in.
    fn eligible_by_uid(&self, uid: u32, username: &str) -> Result<Option<Account>, ApiError> {
        let Some(account) = self.inner.accounts.by_uid(uid)? else {
            return Ok(None);
        };
        if account.name != username {
            return Ok(None);
        }
        match self.inner.policy.check(&account) {
            Ok(()) => Ok(Some(account)),
            Err(reason) => {
                eprintln!("refusing `{username}`: {reason}");
                Ok(None)
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
        Ok(jsonf! {
            "status": "authenticated",
            token,
            "session": session_json(&session, None),
            "user": { "uid": account.uid, "username": account.name, "admin": account.is_admin() },
        })
    }

    fn authenticate(&self, client: ClientKind, token: Option<&str>) -> Result<Caller, ApiError> {
        let token = token.ok_or_else(ApiError::unauthenticated)?;
        let now = self.now();
        let session =
            self.inner
                .sessions
                .validate(token, client, now)
                .map_err(|error| match error {
                    SessionError::WrongClient => ApiError::new(
                        ErrorCode::WrongClient,
                        "this token was issued to the other local client",
                    ),
                    SessionError::Invalid | SessionError::Expired => ApiError::unauthenticated(),
                })?;
        let revoke = |session: &Session| {
            let id = session.id.clone();
            self.inner.sessions.revoke(|s| s.id == id).ok();
            ApiError::unauthenticated()
        };
        let mut groups = Vec::new();
        let principal = match session.kind {
            SessionKind::Setup => {
                if self.inner.setup.is_complete() {
                    return Err(revoke(&session));
                }
                Principal::Setup
            }
            SessionKind::User => {
                let (Some(uid), Some(username)) = (session.uid, session.username.clone()) else {
                    return Err(revoke(&session));
                };
                // Account state is checked on every request, so locking or
                // deleting an account ends its sessions immediately.
                let Some(account) = self.eligible_by_uid(uid, &username)? else {
                    return Err(revoke(&session));
                };
                let epoch = self
                    .record(uid, &username)?
                    .map_or(0, |record| record.session_epoch);
                if session.epoch != epoch {
                    return Err(revoke(&session));
                }
                let admin = account.is_admin();
                groups = account.groups;
                Principal::User {
                    uid,
                    username,
                    admin,
                    permissions: if admin {
                        authz::Permissions::new()
                    } else {
                        self.inner.grants.effective(uid)?
                    },
                }
            }
        };
        Ok(Caller {
            client,
            session,
            principal,
            groups,
        })
    }

    // --- Login -----------------------------------------------------------

    async fn auth_password(&self, client: ClientKind, p: PasswordParams) -> ApiResult {
        if p.username.is_empty() || p.password.is_empty() || p.username.len() > 256 {
            return Err(ApiError::invalid_credentials());
        }
        let outcome = {
            let _permit = self
                .inner
                .pam
                .acquire()
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
            let passwords = Arc::clone(&self.inner.passwords);
            let PasswordParams {
                username,
                password,
                remote_addr,
            } = p.clone();
            tokio::task::spawn_blocking(move || {
                passwords.authenticate(&username, &password, remote_addr.as_deref())
            })
            .await
            .map_err(|error| anyhow::anyhow!(error))?
        };
        match &outcome {
            PamOutcome::Denied => {
                eprintln!("password login failed for `{}`", p.username);
                return Err(ApiError::invalid_credentials());
            }
            PamOutcome::PasswordExpired | PamOutcome::Success => {}
            PamOutcome::Error(error) => {
                return Err(anyhow::anyhow!("PAM failed: {error}").into());
            }
        }
        // Eligibility is checked after PAM so that failures take the same
        // time whether or not the account exists, and before reporting an
        // expired password so that root and other accounts that may never log
        // in do not learn that a guess was right.
        let Some(account) = self.eligible_by_name(&p.username)? else {
            return Err(ApiError::invalid_credentials());
        };
        if outcome == PamOutcome::PasswordExpired {
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
        Ok(jsonf! {
            "status": "second_factor_required",
            pending,
            "methods": ["totp", "recovery_code"],
            expires_at,
        })
    }

    /// Check a TOTP code or recovery code against `record`, consuming it.
    ///
    /// Wrong TOTP codes are counted on the record, across logins, so knowing
    /// the password does not give unlimited guesses at the 6-digit code: after
    /// [`SECOND_FACTOR_FREE_FAILURES`] each attempt waits twice as long as the
    /// last, up to [`SECOND_FACTOR_MAX_BACKOFF`], and fails with
    /// [`SecondFactorLocked`] meanwhile. Recovery codes (50 bits each) are too
    /// strong to guess and stay usable during the wait, so someone holding
    /// the password cannot lock the real user out of their account with it.
    fn verify_second_factor(
        &self,
        record: &mut UserRecord,
        code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<Option<AuthMethod>> {
        let now = self.now();
        if code.is_some() && now < record.second_factor_retry_at {
            bail!(SecondFactorLocked {
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
            _ => bail!(BadSecondFactor),
        }
    }

    fn auth_second_factor(&self, client: ClientKind, p: SecondFactorParams) -> ApiResult {
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
        match verified {
            Ok(Some(method)) => self.issue_user_session(client, &account, method),
            Ok(None) => {
                eprintln!("second factor failed for `{}`", login.username);
                login.attempts = login.attempts.saturating_add(1);
                if login.attempts < SECOND_FACTOR_ATTEMPTS {
                    let expires_at = login.expires_at;
                    self.inner.logins.restore(
                        p.pending,
                        Some(&user_owner(login.uid)),
                        login,
                        expires_at,
                        now,
                    );
                }
                Err(ApiError::invalid_credentials())
            }
            Err(error) if error.is::<BadSecondFactor>() => {
                let expires_at = login.expires_at;
                self.inner.logins.restore(
                    p.pending,
                    Some(&user_owner(login.uid)),
                    login,
                    expires_at,
                    now,
                );
                Err(ApiError::bad_request(BadSecondFactor))
            }
            Err(error) if error.is::<SecondFactorLocked>() => {
                let retry_after = SecondFactorLocked::retry_after(&error);
                let expires_at = login.expires_at;
                self.inner.logins.restore(
                    p.pending,
                    Some(&user_owner(login.uid)),
                    login,
                    expires_at,
                    now,
                );
                Err(ApiError::rate_limited(retry_after))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn webauthn(&self) -> Result<Arc<Webauthn>, ApiError> {
        self.inner
            .webauthn
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(passkeys_unavailable)
    }

    fn auth_passkey_begin(&self, client: ClientKind, p: &PasskeyBeginParams) -> ApiResult {
        let webauthn = self.webauthn()?;
        let known = match p.username.as_deref() {
            Some(name) => self.eligible_by_name(name)?.and_then(|account| {
                let record = self.record(account.uid, &account.name).ok()??;
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
                Authentication {
                    client,
                    state,
                    expires_at,
                },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(CEREMONY_TTL))?;
        Ok(jsonf! { ceremony, options, expires_at })
    }

    async fn auth_passkey_finish(&self, client: ClientKind, p: PasskeyFinishParams) -> ApiResult {
        let webauthn = self.webauthn()?;
        let now = self.now();
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
        // log in: check eligibility and run PAM's account stack.
        let Some(account) = self.eligible_by_uid(uid, &username)? else {
            return Err(ApiError::invalid_credentials());
        };
        let outcome = {
            let _permit = self
                .inner
                .pam
                .acquire()
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
            let passwords = Arc::clone(&self.inner.passwords);
            let name = account.name.clone();
            let rhost = p.remote_addr.clone();
            tokio::task::spawn_blocking(move || passwords.check_account(&name, rhost.as_deref()))
                .await
                .map_err(|error| anyhow::anyhow!(error))?
        };
        match outcome {
            // An expired password does not stop a passwordless login.
            PamOutcome::Success | PamOutcome::PasswordExpired => {}
            PamOutcome::Denied => {
                eprintln!("passkey login refused by PAM account stack for `{username}`");
                return Err(ApiError::invalid_credentials());
            }
            PamOutcome::Error(error) => return Err(anyhow::anyhow!("PAM failed: {error}").into()),
        }

        let updated = self.inner.users.update(uid, &username, |record| {
            let stored = record
                .passkeys
                .iter_mut()
                .find(|stored| stored.passkey.cred_id() == result.cred_id())
                .context("the passkey was removed")?;
            stored.passkey.update_credential(&result);
            stored.last_used_at = Some(now);
            Ok(())
        });
        if let Err(error) = updated {
            eprintln!("passkey login for `{username}` failed: {error:#}");
            return Err(ApiError::invalid_credentials());
        }
        self.issue_user_session(client, &account, AuthMethod::Passkey)
    }

    // --- Setup -----------------------------------------------------------

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

    fn admin_exists(&self) -> Result<bool> {
        for name in self.inner.accounts.names()? {
            if let Some(account) = self.inner.accounts.by_name(&name)?
                && account.is_admin()
                && self.inner.policy.check(&account).is_ok()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn setup_status(&self, client: ClientKind, token: Option<&str>) -> ApiResult {
        let mut status = self.hello();
        // Callers allowed to drive setup also learn whether an administrator
        // already exists, so the OOBE can skip creating one.
        if let Some(token) = token {
            let caller = self.authenticate(client, Some(token))?;
            if caller.require_setup_or_admin().is_ok() {
                status["admin_exists"] = Value::Bool(self.admin_exists()?);
            }
        }
        Ok(status)
    }

    fn setup_redeem(&self, client: ClientKind, p: &RedeemParams) -> ApiResult {
        require_client(client, ClientKind::Oobe)?;
        // Logged with every attempt; escaped, as the OOBE passes it through.
        let from = p.remote_addr.as_deref().map_or_else(
            || "an unknown address".to_owned(),
            |addr| {
                addr.chars()
                    .take(64)
                    .collect::<String>()
                    .escape_debug()
                    .to_string()
            },
        );
        // The per-address throttle only applies when the OOBE says who is
        // asking; otherwise every browser would share one bucket. Addresses
        // are grouped like login ceremonies (any port, IPv6 by /64), and
        // text that is not an address shares one bucket, so it can neither
        // dodge the throttle nor fill its table.
        let throttle_key = p.remote_addr.as_deref().map(|addr| {
            passkey::source_owner(Some(addr)).unwrap_or_else(|| UNPARSEABLE_ADDRESS.to_owned())
        });
        let now = self.now();
        // Held until the outcome is recorded, so concurrent attempts from one
        // address are checked one after another.
        let mut throttle = self.inner.redeem_throttle.lock();
        if let Some(key) = &throttle_key
            && let Err(retry_after) = throttle.check(key, now)
        {
            eprintln!(
                "setup code attempt from {from}: refused, this address must wait {retry_after}s"
            );
            return Err(ApiError::rate_limited(retry_after));
        }
        let key = self.key()?;
        match self.inner.setup.redeem(&key, &p.code, now)? {
            Ok(()) => {
                eprintln!("setup code attempt from {from}: accepted");
                if let Some(key) = &throttle_key {
                    throttle.succeeded(key);
                }
            }
            Err(RedeemError::Complete) => {
                eprintln!("setup code attempt from {from}: setup has already completed");
                return Err(ApiError::new(
                    ErrorCode::SetupComplete,
                    "setup has already completed",
                ));
            }
            Err(RedeemError::RateLimited { retry_after }) => {
                eprintln!(
                    "setup code attempt from {from}: refused, all addresses must wait {retry_after}s"
                );
                return Err(ApiError::rate_limited(retry_after));
            }
            Err(RedeemError::Invalid) => {
                eprintln!("setup code attempt from {from}: wrong code");
                if let Some(key) = &throttle_key {
                    throttle.failed(key, now);
                }
                return Err(ApiError::invalid_credentials());
            }
        }
        drop(throttle);
        let (token, session) = self.inner.sessions.issue(
            NewSession {
                uid: None,
                username: None,
                client,
                kind: SessionKind::Setup,
                method: AuthMethod::SetupCode,
                epoch: 0,
            },
            self.now(),
        )?;
        eprintln!("issued a setup session");
        Ok(jsonf! {
            "status": "authenticated",
            token,
            "session": session_json(&session, None),
            "admin_exists": self.admin_exists()?,
        })
    }

    /// Write the setup marker, then hand over to the dashboard: start it,
    /// and stop the OOBE [`HANDOFF_SECONDS`] later from a transient timer,
    /// so this response (with the dashboard's URL) reaches the OOBE first.
    async fn setup_complete(&self, caller: &Caller) -> ApiResult {
        caller.require_setup_or_admin()?;
        let by = caller.user().ok().map(|(_, name)| name.to_owned());
        self.finish_setup(by.as_deref())?;
        // Setup is complete now, so the handoff must run whatever happens
        // here. A failure only leaves setup sessions in the session file:
        // they stop working anyway, as `authenticate` refuses them once
        // the completion marker exists.
        if let Err(error) = self
            .inner
            .sessions
            .revoke(|session| session.kind == SessionKind::Setup)
        {
            eprintln!("failed to revoke setup sessions: {error:#}");
        }
        let this = self.clone();
        let handoff = tokio::task::spawn_blocking(move || this.start_handoff(true))
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(jsonf! {
            "complete": true,
            "dashboard_url": self.dashboard_url(),
            "handoff_in_seconds": HANDOFF_SECONDS,
            handoff,
        })
    }

    /// The dashboard's URL from the access configuration, if there is one.
    fn dashboard_url(&self) -> Option<String> {
        AccessConfig::load(&self.inner.config.access_path())
            .ok()
            .flatten()
            .and_then(|access| access.origin_string().ok())
    }

    /// Start the dashboard and stop the OOBE: after [`HANDOFF_SECONDS`]
    /// through a transient timer when `delayed`, right away otherwise.
    /// Failures are reported, not returned: setup is already complete.
    ///
    /// The dashboard is started with `--no-block`: the first start of its
    /// Quadlet may pull the image, which can take minutes.
    fn start_handoff(&self, delayed: bool) -> Handoff {
        let host = &self.inner.host;
        let dashboard_error = error_text(host.systemctl(&["--no-block", "start", DASHBOARD_UNIT]));
        if let Some(error) = &dashboard_error {
            eprintln!("setup handoff: failed to start the dashboard: {error}");
        }
        let oobe_error = error_text(if delayed {
            self.schedule_finish_handoff()
        } else {
            self.finish_handoff().map(drop)
        });
        if let Some(error) = &oobe_error {
            eprintln!("setup handoff: failed to stop the OOBE: {error}");
        }
        Handoff {
            dashboard_started: dashboard_error.is_none(),
            dashboard_error,
            oobe_stop_scheduled: delayed && oobe_error.is_none(),
            oobe_error,
        }
    }

    /// Run `tetra setup finish-handoff` from a transient timer in
    /// [`HANDOFF_SECONDS`], with this service's state and Caddy directories.
    fn schedule_finish_handoff(&self) -> Result<()> {
        let config = &self.inner.config;
        let on_active = format!("--on-active={HANDOFF_SECONDS}");
        let unit = format!("--unit={HANDOFF_UNIT}");
        let binary = config.tetra_binary.to_string_lossy();
        let state_dir = config.state_dir.to_string_lossy();
        let caddy_sites_dir = config.caddy_sites_dir.to_string_lossy();
        self.inner.host.run(
            "systemd-run",
            &[
                &on_active,
                &unit,
                "--description=Hand over from the Ultramarine Server setup to the dashboard",
                "--collect",
                &binary,
                "setup",
                "finish-handoff",
                "--state-dir",
                &state_dir,
                "--caddy-sites-dir",
                &caddy_sites_dir,
            ],
        )
    }

    /// The end of the handoff, run by the transient timer
    /// (`tetra setup finish-handoff`): stop and disable the OOBE and the
    /// setup-code unit (either may not be installed), and then remove the
    /// OOBE's Caddy site. The site is what [`Self::resume_handoff`] retries
    /// on, so it stays when stopping a unit failed.
    ///
    /// # Errors
    /// Fails before setup has completed, or when a step fails (the other
    /// unit is still stopped).
    pub fn finish_handoff(&self) -> Result<Value> {
        ensure!(
            self.inner.setup.is_complete(),
            "setup has not completed; the OOBE is still needed"
        );
        let mut errors = Vec::new();
        // One unit at a time: systemctl refuses a whole call naming a unit
        // that is not installed, and a host without one still needs the
        // other stopped.
        for unit in [OOBE_UNIT, SETUP_CODE_UNIT] {
            match error_text(self.inner.host.systemctl(&["disable", "--now", unit])) {
                Some(error) if is_missing_unit(&error) => {
                    eprintln!("setup handoff: {unit} is not installed");
                }
                Some(error) => errors.push(error),
                None => {}
            }
        }
        #[cfg(feature = "reverse-proxy")]
        let site_removed = errors.is_empty()
            && self.sync_setup_site(false, false).unwrap_or_else(|error| {
                errors.push(format!("{error:#}"));
                false
            });
        #[cfg(not(feature = "reverse-proxy"))]
        let site_removed = false;
        ensure!(errors.is_empty(), "{}", errors.join("; "));
        Ok(jsonf! { "oobe_stopped": true, "setup_site_removed": site_removed })
    }

    /// Run at startup: finish a handoff that setup completed but its timer
    /// did not (a transient timer does not survive a reboot, and starting it
    /// may have failed), which the OOBE's Caddy site still being there shows.
    /// Failures are logged.
    pub fn resume_handoff(&self) {
        #[cfg(feature = "reverse-proxy")]
        {
            use crate::agent::modules::reverse_proxy::SETUP_SITE_FILE;
            let site = self.inner.config.caddy_sites_dir.join(SETUP_SITE_FILE);
            if self.inner.setup.is_complete() && site.exists() {
                eprintln!("setup handoff: setup is complete but the OOBE's site remains; finishing");
                if let Err(error) = self.finish_handoff() {
                    eprintln!("setup handoff: failed to finish: {error:#}");
                }
            }
        }
    }

    /// Write the setup marker once an eligible administrator exists.
    fn finish_setup(&self, by: Option<&str>) -> Result<(), ApiError> {
        if self.inner.setup.is_complete() {
            return Err(ApiError::new(
                ErrorCode::SetupComplete,
                "setup has already completed",
            ));
        }
        if !self.admin_exists()? {
            return Err(ApiError::new(
                ErrorCode::SetupIncomplete,
                "create an administrator (a member of ultramarine-admin or wheel who can log in) first",
            ));
        }
        self.inner.setup.complete(by, self.now())?;
        eprintln!("setup completed; the setup code is disabled");
        Ok(())
    }

    /// Complete setup from the root console (`tetra setup complete`), with the
    /// same checks as the `setup.complete` operation. Setup sessions held by a
    /// running daemon stop working on their next request, because every
    /// request re-checks the completion marker; this process does not rewrite
    /// the daemon's session file.
    ///
    /// # Errors
    /// Fails when setup has already completed, no eligible administrator
    /// exists, or the marker cannot be written.
    pub fn complete_setup_from_console(&self) -> Result<Handoff> {
        self.finish_setup(Some("console"))
            .map_err(|error| anyhow::anyhow!(error.message))?;
        Ok(self.start_handoff(false))
    }

    /// Generate (if needed) and publish the setup code for the console, and
    /// write the OOBE's Caddy site. Returns `None` once setup has completed;
    /// the site is then left alone, as it marks an unfinished handoff
    /// ([`Self::finish_handoff`] removes it).
    ///
    /// # Errors
    /// Fails when the code cannot be stored or published. A Caddy failure is
    /// only logged: the console must still show the code.
    pub fn publish_setup_code(&self) -> Result<Option<String>> {
        let key = self.key()?;
        let code = self.inner.setup.ensure_code(&key, self.now())?;
        match &code {
            Some(code) => self.inner.setup.publish(code)?,
            None => self.inner.setup.unpublish()?,
        }
        // `--no-block`: at boot this runs before Caddy starts.
        #[cfg(feature = "reverse-proxy")]
        if code.is_some()
            && let Err(error) = self.sync_setup_site(true, true)
        {
            eprintln!("failed to update the OOBE's Caddy site: {error:#}");
        }
        Ok(code)
    }

    /// Write (during setup) or remove (after it) the OOBE's Caddy site and
    /// reload Caddy if it changed, without waiting for the reload when
    /// `no_block`. Returns whether the site changed.
    #[cfg(feature = "reverse-proxy")]
    fn sync_setup_site(&self, setup: bool, no_block: bool) -> Result<bool> {
        use crate::agent::modules::reverse_proxy::{remove_setup_site, write_setup_site};
        let dir = &self.inner.config.caddy_sites_dir;
        let changed = if setup {
            write_setup_site(dir)?
        } else {
            remove_setup_site(dir)?
        };
        if changed {
            let reload = ["--no-block", "try-reload-or-restart", CADDY_UNIT];
            self.inner
                .host
                .systemctl(if no_block { &reload } else { &reload[1..] })?;
        }
        Ok(changed)
    }

    /// SHA-256 fingerprint of Caddy's internal CA root, as `AA:BB:...`, for
    /// the console to show next to the OOBE's address. `None` until Caddy has
    /// created its CA (on its first start with a `tls internal` site).
    #[must_use]
    pub fn internal_ca_fingerprint(&self) -> Option<String> {
        let pem = fs::read(&self.inner.config.caddy_root_ca).ok()?;
        let der = rustls_pemfile::certs(&mut pem.as_slice()).next()?.ok()?;
        Some(fingerprint(&der))
    }

    // --- Sessions --------------------------------------------------------

    fn session_info(caller: &Caller) -> Value {
        let user = match &caller.principal {
            Principal::User {
                uid,
                username,
                admin,
                ..
            } => jsonf! { uid, username, admin },
            _ => Value::Null,
        };
        let permissions = match &caller.principal {
            Principal::User { admin: true, .. } => jsonf! { "all": true },
            Principal::User { permissions, .. } => json_value(permissions),
            Principal::Setup => {
                jsonf! {
                    "setup": authz::SETUP_ALLOWED.iter().map(|(m, a)| format!("{m}.{a}")).collect::<Vec<_>>(),
                    "operations": authz::SETUP_OPERATIONS,
                }
            }
            Principal::RemoteController => Value::Null,
        };
        jsonf! {
            "session": session_json(&caller.session, Some(&caller.session)),
            user,
            permissions,
        }
    }

    fn session_logout(&self, caller: &Caller) -> ApiResult {
        let id = caller.session.id.clone();
        self.inner.sessions.revoke(|session| session.id == id)?;
        Ok(jsonf! { "revoked": 1 })
    }

    fn session_list(&self, caller: &Caller, p: UidParams) -> ApiResult {
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
        Ok(jsonf! { sessions })
    }

    fn session_revoke(&self, caller: &Caller, p: &SessionIdParams) -> ApiResult {
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
        Ok(jsonf! { revoked })
    }

    fn admin_sessions_revoke(&self, caller: &Caller, p: RequiredUidParams) -> ApiResult {
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
        Ok(jsonf! { revoked })
    }

    fn admin_actions(&self, caller: &Caller, p: ActionsParams) -> ApiResult {
        caller.require_admin()?;
        let actions = self
            .inner
            .audit
            .recent(p.limit.unwrap_or(DEFAULT_ACTION_LOG_LIMIT), p.origin)?;
        Ok(jsonf! { actions })
    }

    // --- Second factor ---------------------------------------------------

    fn account_status(&self, caller: &Caller) -> ApiResult {
        let (uid, username) = caller.user()?;
        let record = self.record(uid, username)?;
        Ok(jsonf! {
            "totp_enrolled": record.as_ref().is_some_and(|r| r.totp.is_some()),
            "recovery_codes_left": record.as_ref().map_or(0, UserRecord::recovery_codes_left),
            "passkeys": record.as_ref().map_or(0, |r| r.passkeys.len()),
            "passkeys_available": self.webauthn().is_ok(),
        })
    }

    fn totp_begin(&self, caller: &Caller) -> ApiResult {
        let (uid, username) = caller.user()?;
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
        Ok(jsonf! { enrollment, "secret": secret_base32, otpauth_uri, expires_at })
    }

    fn totp_confirm(&self, caller: &Caller, p: TotpConfirmParams) -> ApiResult {
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
                ensure!(record.totp.is_none(), AlreadyEnrolled);
                record.totp = Some(TotpRecord {
                    secret: sealed,
                    enrolled_at: now,
                    last_step: Some(step),
                    extra: super::store::Extra::new(),
                });
                record.recovery_codes = stored;
                Ok(())
            })
            .map_err(|error| {
                if error.is::<AlreadyEnrolled>() {
                    ApiError::new(ErrorCode::Conflict, AlreadyEnrolled.to_string())
                } else {
                    error.into()
                }
            })?;
        eprintln!("`{username}` enrolled TOTP");
        Ok(jsonf! { "recovery_codes": codes })
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
            ensure!(record.totp.is_some(), NotEnrolled);
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
            Err(error) if error.is::<NotEnrolled>() => {
                Err(ApiError::new(ErrorCode::NotFound, NotEnrolled.to_string()))
            }
            Err(error) if error.is::<BadSecondFactor>() => {
                Err(ApiError::bad_request(BadSecondFactor))
            }
            Err(error) if error.is::<SecondFactorLocked>() => Err(ApiError::rate_limited(
                SecondFactorLocked::retry_after(&error),
            )),
            Err(error) => Err(error.into()),
        }
    }

    fn totp_disable(&self, caller: &Caller, p: &CodeParams) -> ApiResult {
        self.with_second_factor(caller, p, |record| {
            record.totp = None;
            record.recovery_codes.clear();
        })?;
        Ok(jsonf! { "totp_enrolled": false })
    }

    fn recovery_regenerate(&self, caller: &Caller, p: &CodeParams) -> ApiResult {
        let (codes, stored) = recovery::generate();
        self.with_second_factor(caller, p, |record| record.recovery_codes = stored)?;
        Ok(jsonf! { "recovery_codes": codes })
    }

    // --- Passkey registration -------------------------------------------

    fn passkey_register_begin(&self, caller: &Caller, p: PasskeyNameParams) -> ApiResult {
        let webauthn = self.webauthn()?;
        let (uid, username) = caller.user()?;
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
                    expires_at,
                },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(CEREMONY_TTL))?;
        Ok(jsonf! { ceremony, options, expires_at })
    }

    fn passkey_register_finish(&self, caller: &Caller, p: PasskeyRegisterParams) -> ApiResult {
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
        // A credential must belong to exactly one account.
        if self
            .inner
            .users
            .all()?
            .iter()
            .any(|record| record.passkeys.iter().any(|stored| stored.id == id))
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "this passkey is already registered",
            ));
        }
        let name = match p.name {
            Some(name) => passkey_name(Some(name))?,
            None => registration.name,
        };
        self.inner.users.update(uid, username, |record| {
            record.passkeys.push(PasskeyRecord {
                id: id.clone(),
                name: name.clone(),
                created_at: now,
                last_used_at: None,
                passkey,
                extra: super::store::Extra::new(),
            });
            Ok(())
        })?;
        eprintln!("`{username}` registered a passkey");
        Ok(jsonf! { id, name, "created_at": now })
    }

    fn passkey_list(&self, caller: &Caller) -> ApiResult {
        let (uid, username) = caller.user()?;
        let passkeys: Vec<Value> = self
            .record(uid, username)?
            .map(|record| record.passkeys)
            .unwrap_or_default()
            .iter()
            .map(|stored| jsonf! { stored.id, stored.name, stored.created_at, stored.last_used_at })
            .collect();
        Ok(jsonf! { passkeys })
    }

    fn passkey_remove(&self, caller: &Caller, p: &PasskeyIdParams) -> ApiResult {
        let (uid, username) = caller.user()?;
        let removed = self.inner.users.update(uid, username, |record| {
            let before = record.passkeys.len();
            record.passkeys.retain(|stored| stored.id != p.id);
            Ok(before != record.passkeys.len())
        })?;
        if !removed {
            return Err(ApiError::new(ErrorCode::NotFound, "no such passkey"));
        }
        Ok(jsonf! { "removed": p.id })
    }

    // --- Grants ----------------------------------------------------------

    fn grants_get(&self, caller: &Caller, p: UidParams) -> ApiResult {
        caller.require_admin()?;
        if let Some(uid) = p.uid {
            return Ok(jsonf! {
                uid,
                "grants": self.inner.grants.get(uid)?,
                "effective": self.inner.grants.effective(uid)?,
            });
        }
        Ok(jsonf! { "grants": self.inner.grants.all()? })
    }

    fn grants_set(&self, caller: &Caller, p: &GrantsSetParams) -> ApiResult {
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
            jsonf! { "uid": account.uid, grants, "effective": self.inner.grants.effective(account.uid)? },
        )
    }

    // --- Access ----------------------------------------------------------

    fn access_get(&self) -> ApiResult {
        let access = AccessConfig::load(&self.inner.config.access_path())?;
        Ok(jsonf! { access, "passkeys_available": self.webauthn().is_ok() })
    }

    async fn access_set(&self, caller: &Caller, request: AccessRequest) -> ApiResult {
        caller.require_setup_or_admin()?;
        let config = AccessConfig::from_request(&request, &self.inner.config.dashboard_upstream)
            .map_err(ApiError::bad_request)?;
        let this = self.clone();
        let applied =
            tokio::task::spawn_blocking(move || this.set_access(config, request.dns_credentials))
                .await
                .map_err(|error| anyhow::anyhow!(error))??;
        self.record_action(caller, "access-set", "access", "set", Ok(()));
        Ok(jsonf! {
            "access": applied.config,
            "passkeys_available": self.webauthn().is_ok(),
            "dashboard_url": applied.origin,
            "dashboard_site": applied.dashboard_site,
            "caddy": applied.caddy,
            "dashboard_env": applied.dashboard_env,
        })
    }

    /// Apply a validated `access.set`, one at a time.
    ///
    /// Everything is read and rendered before anything changes, so a
    /// rejected request changes nothing. Then the dashboard's site is
    /// written, and only after it the DNS-01 credentials are replaced or
    /// forgotten; then `access.json` and the relying party are updated.
    /// Reloading Caddy and updating the dashboard's `ORIGIN` come last, and
    /// their failures are reported in the result: the new configuration is
    /// already stored by then.
    fn set_access(
        &self,
        mut config: AccessConfig,
        given: Option<DnsCredentials>,
    ) -> Result<AppliedAccess, ApiError> {
        let _serialized = self
            .inner
            .access_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let webauthn = config.webauthn().map_err(ApiError::bad_request)?;
        let origin = config.origin_string().map_err(ApiError::bad_request)?;
        #[cfg(feature = "remote-access")]
        self.ensure_tailscale_port_unchanged(&config)?;
        let dns = self.dns_credentials(&config, given)?;
        #[cfg(feature = "reverse-proxy")]
        let caddy_files = self.render_caddy_files(&config, dns)?;
        #[cfg(not(feature = "reverse-proxy"))]
        drop(dns);
        let dashboard_env = self.render_dashboard_env(&origin)?;

        #[cfg(feature = "reverse-proxy")]
        let (dashboard_site, caddy_changes) = self.write_caddy_files(&caddy_files)?;
        config.save(&self.inner.config.access_path())?;
        *self
            .inner
            .webauthn
            .write()
            .unwrap_or_else(PoisonError::into_inner) = webauthn.map(Arc::new);
        // Ceremonies in flight were made for the previous relying party.
        self.inner.registrations.remove_where(|_| true);
        self.inner.authentications.remove_where(|_| true);

        #[cfg(feature = "reverse-proxy")]
        let caddy = self.reload_caddy(caddy_changes);
        #[cfg(not(feature = "reverse-proxy"))]
        let (dashboard_site, caddy) = (Value::Null, Value::Null);
        let dashboard_env = self.write_dashboard_env(&dashboard_env);
        // Catalog entries' URLs depend on the access configuration.
        if let Err(error) = self.inner.launcher.refresh_public_page(Some(&config)) {
            eprintln!("failed to write the launcher's public page: {error:#}");
        }
        Ok(AppliedAccess {
            config,
            origin,
            dashboard_site,
            caddy,
            dashboard_env,
        })
    }

    /// Refuse to change the dashboard's port while Tailscale is set up:
    /// `remote_access.tailscale_up` forwards the port it read, and would keep
    /// forwarding it to nothing.
    #[cfg(feature = "remote-access")]
    fn ensure_tailscale_port_unchanged(&self, config: &AccessConfig) -> Result<(), ApiError> {
        use super::access::HTTPS_PORT;
        let paths = &self.inner.config;
        if !crate::agent::modules::remote_access::tailscale_set_up(&paths.systemd_dir) {
            return Ok(());
        }
        let current = AccessConfig::load(&paths.access_path())?
            .and_then(|current| current.port)
            .unwrap_or(HTTPS_PORT);
        let port = config.port.unwrap_or(HTTPS_PORT);
        if port == current {
            return Ok(());
        }
        Err(ApiError::new(
            ErrorCode::Conflict,
            format!(
                "Tailscale forwards port {current} to the dashboard; run \
                 remote_access.tailscale_disable before changing the port to {port}, \
                 then remote_access.tailscale_up again"
            ),
        ))
    }

    /// The DNS-01 credentials for `config`: the ones given, or the ones
    /// stored for the same provider.
    fn dns_credentials(
        &self,
        config: &AccessConfig,
        given: Option<DnsCredentials>,
    ) -> Result<Option<StoredDnsCredentials>, ApiError> {
        let (AcmeChallenge::Dns01, Some(provider)) = (config.challenge, config.dns_provider) else {
            return Ok(None);
        };
        if let Some(credentials) = given {
            return Ok(Some(StoredDnsCredentials {
                provider,
                credentials,
            }));
        }
        let secrets = SecretStore::new(self.inner.config.secrets_dir());
        let stored = secrets
            .get(self.inner.sealer.as_ref(), DNS_CREDENTIALS)?
            .map(|bytes| serde_json::from_slice::<StoredDnsCredentials>(&bytes))
            .transpose()
            .context("stored DNS credentials are unreadable")?
            .filter(|stored| stored.provider == provider);
        stored.map(Some).ok_or_else(|| {
            ApiError::bad_request(format!(
                "dns_credentials are required for {}",
                provider.name()
            ))
        })
    }

    /// The dashboard's site and, for DNS-01, the credentials to seal and
    /// Caddy's environment file and drop-in.
    #[cfg(feature = "reverse-proxy")]
    fn render_caddy_files(
        &self,
        config: &AccessConfig,
        dns: Option<StoredDnsCredentials>,
    ) -> Result<CaddyFiles, ApiError> {
        let paths = &self.inner.config;
        let site = config
            .dashboard_site(
                Some(&paths.public_dir),
                dns.as_ref().map(|stored| &stored.credentials),
            )
            .and_then(|site| site.render())
            .map_err(ApiError::bad_request)?;
        let dns = dns
            .map(|stored| -> Result<DnsFiles> {
                Ok(DnsFiles {
                    sealed: serde_json::to_vec(&stored)
                        .context("failed to encode DNS credentials")?,
                    env: super::dns::env_file(stored.provider, &stored.credentials),
                    drop_in: format!(
                        "# Managed by Tetra (access.set): DNS-01 credentials for the dashboard's\n\
                         # certificate, referenced by the site as {{env.TETRA_DNS_*}}.\n\
                         [Service]\n\
                         EnvironmentFile=-{}\n",
                        paths.caddy_env_file.display()
                    ),
                })
            })
            .transpose()?;
        Ok(CaddyFiles { site, dns })
    }

    /// Write the dashboard's site, then seal the DNS-01 credentials and write
    /// Caddy's environment file and drop-in, or forget them all.
    #[cfg(feature = "reverse-proxy")]
    fn write_caddy_files(&self, files: &CaddyFiles) -> Result<(Value, CaddyChanges), ApiError> {
        let paths = &self.inner.config;
        let secrets = SecretStore::new(paths.secrets_dir());
        let drop_in = paths.systemd_dir.join(CADDY_DROP_IN);
        let dashboard_site = crate::agent::modules::reverse_proxy::write_dashboard_site(
            &paths.caddy_sites_dir,
            &files.site,
        )?;
        let changes = if let Some(dns) = &files.dns {
            secrets.put(self.inner.sealer.as_ref(), DNS_CREDENTIALS, &dns.sealed)?;
            let env = store::replace_if_changed(&paths.caddy_env_file, dns.env.as_bytes(), 0o640)?;
            share_with_caddy(&paths.caddy_env_file)?;
            CaddyChanges {
                env,
                drop_in: store::replace_if_changed(&drop_in, dns.drop_in.as_bytes(), 0o644)?,
            }
        } else {
            let changes = CaddyChanges {
                env: store::remove_if_exists(&paths.caddy_env_file)?,
                drop_in: store::remove_if_exists(&drop_in)?,
            };
            secrets.remove(DNS_CREDENTIALS)?;
            changes
        };
        Ok((dashboard_site, changes))
    }

    /// Reload Caddy, or restart it (without waiting, as this request may be
    /// passing through it) when its environment changed. Failures are
    /// reported in the result.
    #[cfg(feature = "reverse-proxy")]
    fn reload_caddy(&self, changes: CaddyChanges) -> Value {
        let host = &self.inner.host;
        let mut errors = Vec::new();
        if changes.drop_in {
            errors.extend(error_text(host.systemctl(&["daemon-reload"])));
        }
        let restart = changes.env || changes.drop_in;
        errors.extend(error_text(if restart {
            host.systemctl(&["--no-block", "try-restart", CADDY_UNIT])
        } else {
            host.systemctl(&["try-reload-or-restart", CADDY_UNIT])
        }));
        let error = if errors.is_empty() {
            None
        } else {
            let error = errors.join("; ");
            eprintln!("access.set: Caddy did not take the new configuration: {error}");
            Some(error)
        };
        jsonf! { "restarted": restart, "reloaded": !restart, error }
    }

    /// The dashboard's environment file with `ORIGIN` set to `origin` and
    /// its other lines kept.
    fn render_dashboard_env(&self, origin: &str) -> Result<DashboardEnv, ApiError> {
        let path = &self.inner.config.dashboard_env_file;
        let read = || -> io::Result<Option<(String, fs::Metadata)>> {
            let mut file = match fs::File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            let mut text = String::new();
            io::Read::read_to_string(&mut file, &mut text)?;
            Ok(Some((text, file.metadata()?)))
        };
        let (existing, metadata) = read()
            .with_context(|| format!("failed to read `{}`", path.display()))?
            .unzip();
        let mut contents = String::new();
        for line in existing
            .iter()
            .flat_map(|existing| existing.lines())
            .filter(|line| !line.trim_start().starts_with("ORIGIN="))
        {
            contents.push_str(line);
            contents.push('\n');
        }
        contents.push_str("ORIGIN=");
        contents.push_str(origin);
        contents.push('\n');
        Ok(DashboardEnv {
            contents,
            origin: origin.to_owned(),
            existing: metadata,
        })
    }

    /// Write the dashboard's environment file and restart the dashboard if it
    /// is running and the file changed. `--no-block`: the dashboard may be
    /// the caller. Failures are reported in the result.
    fn write_dashboard_env(&self, env: &DashboardEnv) -> Value {
        let path = &self.inner.config.dashboard_env_file;
        let (changed, error) =
            match replace_keeping_owner(path, &env.contents, env.existing.as_ref()) {
                Ok(changed) => (changed, None),
                Err(error) => {
                    let error = format!("{error:#}");
                    eprintln!("access.set: failed to write the dashboard's ORIGIN: {error}");
                    (false, Some(error))
                }
            };
        let restart_error = if changed {
            error_text(
                self.inner
                    .host
                    .systemctl(&["--no-block", "try-restart", DASHBOARD_UNIT]),
            )
        } else {
            None
        };
        jsonf! { path, "origin": env.origin, changed, error, restart_error }
    }

    // --- Launcher --------------------------------------------------------

    fn access(&self) -> Option<AccessConfig> {
        AccessConfig::load(&self.inner.config.access_path()).unwrap_or_else(|error| {
            eprintln!("ignoring the access configuration: {error:#}");
            None
        })
    }

    fn launcher_list(&self, caller: &Caller) -> ApiResult {
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

    fn launcher_get(&self, caller: &Caller, p: &LauncherIdParams) -> ApiResult {
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

    fn launcher_set(&self, caller: &Caller, p: LauncherSetParams) -> ApiResult {
        caller.authorize("launcher", "set")?;
        let access = self.access();
        let entry = self
            .inner
            .launcher
            .set(p.id.as_deref(), p.entry, access.as_ref())?
            .map_err(launcher_change_error)?;
        self.record_action(
            caller,
            &format!("launcher-set:{}", entry.id),
            "launcher",
            "set",
            Ok(()),
        );
        Ok(jsonf! { "entry": entry.to_json(true, access.as_ref()) })
    }

    fn launcher_remove(&self, caller: &Caller, p: &LauncherIdParams) -> ApiResult {
        caller.authorize("launcher", "remove")?;
        self.inner
            .launcher
            .remove(&p.id, self.access().as_ref())?
            .map_err(launcher_change_error)?;
        self.record_action(
            caller,
            &format!("launcher-remove:{}", p.id),
            "launcher",
            "remove",
            Ok(()),
        );
        Ok(jsonf! { "removed": p.id })
    }

    fn launcher_public_json(&self) -> ApiResult {
        Ok(jsonf! {
            "enabled": self.inner.launcher.load()?.public_page,
            "path": self.inner.launcher.public_page_path(),
        })
    }

    fn launcher_public_get(&self, caller: &Caller) -> ApiResult {
        caller.authorize("launcher", "public_get")?;
        self.launcher_public_json()
    }

    fn launcher_public_set(&self, caller: &Caller, p: LauncherPublicParams) -> ApiResult {
        caller.authorize("launcher", "public_set")?;
        self.inner
            .launcher
            .set_public_page(p.enabled, self.access().as_ref())?;
        self.record_action(
            caller,
            "launcher-public-set",
            "launcher",
            "public_set",
            Ok(()),
        );
        self.launcher_public_json()
    }

    /// Whether `uid` may open entry `id`: for the dashboard's OIDC provider
    /// and Caddy `forward_auth`, which may run without the user's session (a
    /// token refresh, for example). Dashboard only; no token. Accounts that
    /// may not log in, unknown entries and hidden entries are all `false`.
    fn launcher_can_access(&self, client: ClientKind, p: &CanAccessParams) -> ApiResult {
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
        });
    }

    /// Record that the setup session `session_id` created the account
    /// `name`, which lets it set that account's password and SSH keys.
    pub(crate) fn record_setup_account(&self, session_id: &str, name: &str) -> Result<()> {
        self.inner.sessions.add_created_account(session_id, name)
    }

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

    async fn dispatch(&self, caller: &Caller, id: &str, p: DispatchParams) -> ApiResult {
        caller.authorize(&p.module, &p.action)?;
        // Accounts the setup session creates are the ones it may then set up.
        let created = self.setup_dispatch_guard(caller, &p)?;
        if let Some(field) = authz::admin_only_field(&p.module, &p.payload)
            && !matches!(caller.principal, Principal::RemoteController)
            && !caller.is_admin()
        {
            return Err(ApiError::forbidden(format!(
                "only administrators may set `{field}` on {}.{}",
                p.module, p.action
            )));
        }
        let user = match &caller.principal {
            Principal::User { username, .. } => Some(username.clone()),
            _ => None,
        };
        let command = AgentCommand {
            id: id.to_owned(),
            module: p.module.clone(),
            action: p.action.clone(),
            payload: p.payload,
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
        self.record_action(
            caller,
            id,
            &p.module,
            &p.action,
            response.error.as_deref().map_or(Ok(()), Err),
        );
        if response.ok
            && let Some(name) = created
        {
            self.record_setup_account(&caller.session.id, &name)?;
        }
        if response.ok {
            Ok(response.payload.unwrap_or(Value::Null))
        } else {
            Err(ApiError::new(
                ErrorCode::ActionFailed,
                response.error.unwrap_or_default(),
            ))
        }
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
        Ok(jsonf! {
            "username": account.name,
            "totp_removed": had_totp,
            "recovery_codes_removed": recovery_codes,
            "passkeys_removed": removed_passkeys,
            "sessions_invalidated": true,
        })
    })
}

/// How the setup handoff went: `setup.complete`'s `handoff`. Failures do
/// not undo setup completion.
#[derive(Debug, Clone, Serialize)]
pub struct Handoff {
    /// The dashboard's start job was queued (`systemctl --no-block start`).
    pub dashboard_started: bool,
    pub dashboard_error: Option<String>,
    /// The transient timer that stops the OOBE was started.
    pub oobe_stop_scheduled: bool,
    /// Why the OOBE could not be stopped, or its stop scheduled.
    pub oobe_error: Option<String>,
}

/// What `access.set` did, for its result.
struct AppliedAccess {
    config: AccessConfig,
    /// The dashboard's URL.
    origin: String,
    dashboard_site: Value,
    caddy: Value,
    dashboard_env: Value,
}

/// The Caddy files `access.set` writes, rendered before anything changes.
#[cfg(feature = "reverse-proxy")]
struct CaddyFiles {
    site: String,
    /// `None` without DNS-01, which removes the stored credentials.
    dns: Option<DnsFiles>,
}

#[cfg(feature = "reverse-proxy")]
struct DnsFiles {
    /// [`StoredDnsCredentials`] as JSON, to seal.
    sealed: Vec<u8>,
    /// Caddy's environment file with the secrets.
    env: String,
    /// The `caddy.service` drop-in that loads it.
    drop_in: String,
}

/// Which of Caddy's DNS-01 files `access.set` changed.
#[cfg(feature = "reverse-proxy")]
#[derive(Debug, Clone, Copy)]
struct CaddyChanges {
    env: bool,
    drop_in: bool,
}

/// The dashboard's environment file as `access.set` will write it.
struct DashboardEnv {
    contents: String,
    origin: String,
    /// The current file's metadata, whose mode and owner are kept.
    existing: Option<fs::Metadata>,
}

/// A failure as reported in a result, for steps that must not stop the
/// operation.
fn error_text<T>(result: Result<T>) -> Option<String> {
    result.err().map(|error| format!("{error:#}"))
}

/// Whether a failed `systemctl` call's error says the unit is not installed
/// ("Unit file … does not exist", "Unit … not found", "Unit … not loaded").
fn is_missing_unit(error: &str) -> bool {
    ["does not exist", "not found", "not loaded"]
        .iter()
        .any(|phrase| error.contains(phrase))
}

/// Atomically replace `path` with `contents` unless it already holds them,
/// keeping the mode and (as root) the owner of `existing`, the current file:
/// it may hold secrets for its service. A new file is `0600`. Returns whether
/// the file changed.
fn replace_keeping_owner(
    path: &Path,
    contents: &str,
    existing: Option<&fs::Metadata>,
) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let mode = existing.map_or(0o600, |metadata| metadata.mode() & 0o777);
    let changed = store::replace_if_changed(path, contents.as_bytes(), mode)?;
    if changed
        && nix::unistd::geteuid().is_root()
        && let Some(metadata) = existing
    {
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(metadata.uid())),
            Some(nix::unistd::Gid::from_raw(metadata.gid())),
        )
        .with_context(|| format!("failed to chown `{}`", path.display()))?;
    }
    Ok(changed)
}

/// Make a root-owned file readable by the `caddy` group (`root:caddy`), when
/// running as root and the group exists. systemd reads `EnvironmentFile=` as
/// root either way.
#[cfg(feature = "reverse-proxy")]
fn share_with_caddy(path: &Path) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    match nix::unistd::Group::from_name("caddy")? {
        Some(group) => {
            nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(group.gid))
                .with_context(|| format!("failed to chown `{}`", path.display()))
        }
        None => {
            // Without the group, keep it root-only.
            fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .with_context(|| format!("failed to chmod `{}`", path.display()))
        }
    }
}

/// `AA:BB:...` SHA-256 fingerprint of a DER certificate.
fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .join(":")
}

fn json_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
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

#[derive(Debug)]
struct BadSecondFactor;
impl std::fmt::Display for BadSecondFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pass exactly one of `code` or `recovery_code`")
    }
}
impl std::error::Error for BadSecondFactor {}

#[derive(Debug)]
struct SecondFactorLocked {
    retry_after: i64,
}
impl std::fmt::Display for SecondFactorLocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "too many wrong codes; retry in {} seconds",
            self.retry_after
        )
    }
}
impl std::error::Error for SecondFactorLocked {}
impl SecondFactorLocked {
    fn retry_after(error: &anyhow::Error) -> i64 {
        error
            .downcast_ref::<Self>()
            .map_or(SECOND_FACTOR_MAX_BACKOFF, |locked| locked.retry_after)
    }
}

#[derive(Debug)]
struct NotEnrolled;
impl std::fmt::Display for NotEnrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TOTP is not enrolled")
    }
}
impl std::error::Error for NotEnrolled {}

#[derive(Debug)]
struct AlreadyEnrolled;
impl std::fmt::Display for AlreadyEnrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TOTP is already enrolled; disable it first")
    }
}
impl std::error::Error for AlreadyEnrolled {}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordParams {
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
struct SecondFactorParams {
    pending: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyBeginParams {
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
struct PasskeyFinishParams {
    ceremony: String,
    credential: PublicKeyCredential,
    #[serde(default)]
    remote_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyNameParams {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRegisterParams {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyIdParams {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpConfirmParams {
    enrollment: String,
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemParams {
    code: String,
    /// The browser's address as the OOBE saw it, for logs and the
    /// per-address throttle.
    #[serde(default)]
    remote_addr: Option<String>,
}

impl std::fmt::Debug for RedeemParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedeemParams")
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct UidParams {
    #[serde(default)]
    uid: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredUidParams {
    uid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIdParams {
    id: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionsParams {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    origin: Option<Origin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsSetParams {
    uid: u32,
    /// `{page: "view" | "manage" | null}`; `null` removes the grant.
    grants: BTreeMap<Page, Option<Level>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherIdParams {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherSetParams {
    /// The entry to replace; a new entry is added without one.
    #[serde(default)]
    id: Option<String>,
    entry: EntryInput,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherPublicParams {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanAccessParams {
    uid: u32,
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchParams {
    module: String,
    action: String,
    #[serde(default)]
    payload: Value,
}
