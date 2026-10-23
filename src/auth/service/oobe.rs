//! Setup and the handoff to the dashboard: `setup.*`.

use crate::{
    auth::{
        api::{ApiError, ApiResult, ErrorCode},
        passkey,
        sessions::{AuthMethod, ClientKind, NewSession, SessionKind},
        setup::RedeemError,
    },
    prelude::*,
};

#[cfg(feature = "reverse-proxy")]
use super::CADDY_UNIT;
use super::{
    AuthService, Caller, DASHBOARD_UNIT, HANDOFF_SECONDS, OOBE_UNIT, SETUP_CODE_UNIT, blocking,
    error_text, require_client, session_json,
};

/// The setup-code throttle bucket shared by every `remote_addr` that is not
/// an IP address.
const UNPARSEABLE_ADDRESS: &str = "unparseable";
/// Transient unit that finishes the handoff.
const HANDOFF_UNIT: &str = "tetra-setup-handoff";

impl AuthService {
    // --- Setup -----------------------------------------------------------

    pub(super) fn admin_exists(&self) -> Result<bool> {
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

    pub(super) fn setup_status(&self, client: ClientKind, token: Option<&str>) -> ApiResult {
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

    pub(super) fn setup_redeem(&self, client: ClientKind, p: &RedeemParams) -> ApiResult {
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
        // Unsealed before taking the throttle lock: the first use runs
        // `systemd-creds` (the TPM), which must not stall other addresses.
        let key = self.key()?;
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
    pub(super) async fn setup_complete(&self, caller: &Caller) -> ApiResult {
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
        let handoff = blocking(move || this.start_handoff(true)).await?;
        Ok(jsonf! {
            "complete": true,
            "dashboard_url": self.dashboard_url(),
            "handoff_in_seconds": HANDOFF_SECONDS,
            handoff,
        })
    }

    /// The dashboard's URL from the access configuration, if there is one.
    fn dashboard_url(&self) -> Option<String> {
        self.access()?.origin_string().ok()
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
    #[cfg_attr(not(feature = "reverse-proxy"), allow(clippy::missing_const_for_fn))]
    pub fn resume_handoff(&self) {
        #[cfg(feature = "reverse-proxy")]
        {
            use crate::agent::modules::reverse_proxy::SETUP_SITE_FILE;
            let site = self.inner.config.caddy_sites_dir.join(SETUP_SITE_FILE);
            if self.inner.setup.is_complete() && site.exists() {
                eprintln!(
                    "setup handoff: setup is complete but the OOBE's site remains; finishing"
                );
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
        if !self.inner.setup.complete(by, self.now())? {
            return Err(ApiError::new(
                ErrorCode::SetupComplete,
                "setup has already completed",
            ));
        }
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
        use rustls::pki_types::{CertificateDer, pem::PemObject as _};
        let pem = fs::read(&self.inner.config.caddy_root_ca).ok()?;
        let der = CertificateDer::pem_slice_iter(&pem).next()?.ok()?;
        Some(fingerprint(&der))
    }
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

/// Whether a failed `systemctl` call's error says the unit is not installed
/// ("Unit file … does not exist", "Unit … not found", "Unit … not loaded").
fn is_missing_unit(error: &str) -> bool {
    ["does not exist", "not found", "not loaded"]
        .iter()
        .any(|phrase| error.contains(phrase))
}

/// `AA:BB:...` SHA-256 fingerprint of a DER certificate.
fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .join(":")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedeemParams {
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
