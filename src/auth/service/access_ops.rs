//! How the dashboard is reached: `access.*`, with its Caddy site, DNS-01
//! credentials and the dashboard's `ORIGIN`.

use std::sync::{Arc, PoisonError};

use crate::{
    auth::{
        access::{AccessConfig, AccessRequest, AcmeChallenge},
        api::{ApiError, ApiResult},
        dns::{DnsCredentials, StoredDnsCredentials},
        secrets::{DNS_CREDENTIALS, SecretStore},
        store,
    },
    prelude::*,
};

#[cfg(feature = "remote-access")]
use crate::auth::api::ErrorCode;

#[cfg(feature = "reverse-proxy")]
use super::CADDY_UNIT;
use super::{AuthService, Caller, DASHBOARD_UNIT, blocking, error_text};

/// `caddy.service` drop-in that loads the DNS-01 environment file.
#[cfg(feature = "reverse-proxy")]
const CADDY_DROP_IN: &str = "caddy.service.d/50-tetra.conf";

impl AuthService {
    // --- Access ----------------------------------------------------------

    pub(super) fn access_get(&self) -> ApiResult {
        let access = AccessConfig::load(&self.inner.config.access_path())?;
        Ok(jsonf! { access, "passkeys_available": self.webauthn().is_ok() })
    }

    pub(super) async fn access_set(&self, caller: &Caller, request: AccessRequest) -> ApiResult {
        caller.require_setup_or_admin()?;
        let config = AccessConfig::from_request(&request, &self.inner.config.dashboard_upstream)
            .map_err(ApiError::bad_request)?;
        let this = self.clone();
        let applied = blocking(move || this.set_access(config, request.dns_credentials)).await??;
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
        use crate::auth::access::HTTPS_PORT;
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
                    env: crate::auth::dns::env_file(stored.provider, &stored.credentials),
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
