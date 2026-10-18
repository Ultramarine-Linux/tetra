//! How browsers reach this server: `/var/lib/tetra/access.json`.
//!
//! Set by the OOBE (or an administrator) through `access.set`. It decides
//!
//! - the dashboard's Caddy site, regenerated through the `reverse_proxy`
//!   module on every change, and
//! - the WebAuthn relying party: the RP ID is the hostname and the origin is
//!   `https://<hostname>[:port]`.
//!
//! **Domain mode** covers custom domains and Tailscale `*.ts.net` names; Caddy
//! obtains certificates automatically. **IP mode** serves the dashboard on an
//! IP address with Caddy's internal CA. Browsers do not allow WebAuthn on IP
//! addresses, so passkeys are unavailable in IP mode.
//!
//! This lives in its own file rather than `/etc/tetra/tetra.json` because that
//! file is parsed with `deny_unknown_fields`, and a rolled-back Tetra would
//! refuse a config containing a new section.

use std::net::IpAddr;

use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::Url};

use crate::prelude::*;

use super::store::{self, Extra, Header, Record, Tolerant};

/// Where the dashboard container listens unless `tetra agent-serve
/// --dashboard-upstream` or `access.set` says otherwise. To be confirmed
/// against the dashboard Quadlet's published port.
pub const DEFAULT_DASHBOARD_UPSTREAM: &str = "127.0.0.1:3972";
/// Relying party name shown by browsers and authenticators.
pub const RP_NAME: &str = "Ultramarine Server";
const HTTPS_PORT: u16 = 443;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// A DNS name (custom domain or Tailscale `ts.net`), with automatic HTTPS.
    Domain,
    /// An IP address, with Caddy's internal CA. No passkeys.
    Ip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(flatten)]
    header: Header,
    pub mode: AccessMode,
    /// DNS name in domain mode, IP address in IP mode.
    pub hostname: String,
    /// HTTPS port, when not 443.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default = "default_upstream")]
    pub dashboard_upstream: String,
    #[serde(flatten)]
    extra: Extra,
}

fn default_upstream() -> String {
    DEFAULT_DASHBOARD_UPSTREAM.to_owned()
}

impl Record for AccessConfig {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

/// Just the mode of `access.json`, to recognize a mode from a newer build
/// before parsing the rest. Only read, never written.
#[derive(Serialize, Deserialize)]
struct ModeProbe {
    #[serde(flatten)]
    header: Header,
    mode: Tolerant<AccessMode>,
}

impl Record for ModeProbe {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

/// `access.set` parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    pub mode: AccessMode,
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub dashboard_upstream: Option<String>,
}

impl AccessConfig {
    /// Validate and normalize a request. `default_upstream` is used when the
    /// request does not name the dashboard's address.
    ///
    /// # Errors
    /// Fails when the hostname does not match the mode or is not a valid
    /// name or address.
    pub fn from_request(request: AccessRequest, default_upstream: &str) -> Result<Self> {
        let hostname = match request.mode {
            AccessMode::Domain => validate_dns_name(&request.hostname)?,
            AccessMode::Ip => request
                .hostname
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .with_context(|| format!("`{}` is not an IP address", request.hostname))?
                .to_string(),
        };
        ensure!(request.port != Some(0), "port must not be 0");
        let upstream = request
            .dashboard_upstream
            .unwrap_or_else(|| default_upstream.to_owned())
            .trim()
            .to_owned();
        ensure!(
            upstream.contains(':') && !upstream.contains(char::is_whitespace),
            "dashboard_upstream must be a host:port address"
        );
        Ok(Self {
            header: Header::default(),
            mode: request.mode,
            hostname,
            port: request.port.filter(|port| *port != HTTPS_PORT),
            dashboard_upstream: upstream,
            extra: Extra::new(),
        })
    }

    /// The stored configuration. A mode this build does not know (written by
    /// a newer build) reads as no configuration, so passkeys are off and app
    /// URLs are not built; the file is left as it is until `access.set`
    /// replaces it.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match store::read::<ModeProbe>(path)? {
            None => Ok(None),
            Some(ModeProbe {
                mode: Tolerant::Unknown(mode),
                ..
            }) => {
                eprintln!(
                    "`{}` uses access mode {mode}, which this Tetra does not know; ignoring it",
                    path.display()
                );
                Ok(None)
            }
            Some(_) => store::read(path),
        }
    }

    /// # Errors
    /// Fails when the file cannot be written.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        store::write(path, self)
    }

    /// The hostname as it appears in a URL: IPv6 addresses in brackets.
    #[must_use]
    pub fn url_host(&self) -> String {
        match self.hostname.parse::<IpAddr>() {
            Ok(IpAddr::V6(address)) => format!("[{address}]"),
            _ => self.hostname.clone(),
        }
    }

    /// `https://<host>[:port]`.
    ///
    /// # Errors
    /// Fails only for a hostname that is not a valid URL host.
    pub fn origin(&self) -> Result<Url> {
        let port = self.port.map(|port| format!(":{port}")).unwrap_or_default();
        Url::parse(&format!("https://{}{port}", self.url_host()))
            .context("invalid dashboard origin")
    }

    #[must_use]
    pub fn passkeys_available(&self) -> bool {
        self.mode == AccessMode::Domain
    }

    /// The WebAuthn relying party for this configuration, or `None` in IP
    /// mode.
    ///
    /// # Errors
    /// Fails when webauthn-rs rejects the RP ID or origin.
    pub fn webauthn(&self) -> Result<Option<Webauthn>> {
        if !self.passkeys_available() {
            return Ok(None);
        }
        let origin = self.origin()?;
        let webauthn = WebauthnBuilder::new(&self.hostname, &origin)
            .map_err(|error| anyhow::anyhow!("invalid relying party: {error}"))?
            .rp_name(RP_NAME)
            .build()
            .map_err(|error| anyhow::anyhow!("invalid relying party: {error}"))?;
        Ok(Some(webauthn))
    }

    /// The dashboard's Caddy site for this configuration, serving the
    /// launcher's public page from `public_root` when given.
    #[cfg(feature = "reverse-proxy")]
    #[must_use]
    pub fn dashboard_site(
        &self,
        public_root: Option<&Path>,
    ) -> crate::agent::modules::reverse_proxy::DashboardSite {
        use crate::agent::modules::reverse_proxy::{DashboardSite, DashboardTls};
        let port = self.port.map(|port| format!(":{port}")).unwrap_or_default();
        match self.mode {
            AccessMode::Domain => DashboardSite {
                address: format!("{}{port}", self.hostname),
                tls: DashboardTls::Automatic,
                upstream: self.dashboard_upstream.clone(),
                public_root: public_root.map(Path::to_path_buf),
            },
            AccessMode::Ip => DashboardSite {
                address: format!("https://{}{port}", self.url_host()),
                tls: DashboardTls::Internal,
                upstream: self.dashboard_upstream.clone(),
                public_root: public_root.map(Path::to_path_buf),
            },
        }
    }
}

/// Normalize and validate a DNS name: lowercase, no trailing dot, LDH labels,
/// and not an IP address (which belongs in IP mode).
fn validate_dns_name(name: &str) -> Result<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    ensure!(
        name.parse::<IpAddr>().is_err(),
        "`{name}` is an IP address; use IP mode"
    );
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        });
    ensure!(valid, "`{name}` is not a valid hostname");
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mode: AccessMode, hostname: &str, port: Option<u16>) -> AccessRequest {
        AccessRequest {
            mode,
            hostname: hostname.into(),
            port,
            dashboard_upstream: None,
        }
    }

    #[test]
    fn domain_mode_has_an_origin_and_passkeys() {
        let config = AccessConfig::from_request(
            request(AccessMode::Domain, "Server.Example.com.", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(config.hostname, "server.example.com");
        assert_eq!(
            config.origin().unwrap().as_str(),
            "https://server.example.com/"
        );
        assert!(config.webauthn().unwrap().is_some());
    }

    #[test]
    fn tailscale_names_are_domain_mode() {
        let config = AccessConfig::from_request(
            request(AccessMode::Domain, "server.tail1234.ts.net", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert!(config.passkeys_available());
    }

    #[test]
    fn non_default_ports_are_part_of_the_origin() {
        let config = AccessConfig::from_request(
            request(AccessMode::Domain, "server.example.com", Some(8443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(
            config.origin().unwrap().as_str(),
            "https://server.example.com:8443/"
        );
        let default = AccessConfig::from_request(
            request(AccessMode::Domain, "server.example.com", Some(443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(default.port, None);
    }

    #[test]
    fn ip_mode_has_no_passkeys() {
        let config = AccessConfig::from_request(
            request(AccessMode::Ip, "[2001:db8::1]", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(config.hostname, "2001:db8::1");
        assert!(config.webauthn().unwrap().is_none());
        assert_eq!(config.origin().unwrap().as_str(), "https://[2001:db8::1]/");
    }

    #[test]
    fn mode_and_hostname_must_agree() {
        AccessConfig::from_request(
            request(AccessMode::Domain, "192.0.2.1", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap_err();
        AccessConfig::from_request(
            request(AccessMode::Ip, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap_err();
        AccessConfig::from_request(
            request(AccessMode::Domain, "bad name {", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap_err();
    }

    #[cfg(feature = "reverse-proxy")]
    #[test]
    fn builds_dashboard_sites() {
        use crate::agent::modules::reverse_proxy::DashboardTls;
        let domain = AccessConfig::from_request(
            request(AccessMode::Domain, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap()
        .dashboard_site(None);
        assert_eq!(domain.address, "server.example.com");
        assert_eq!(domain.tls, DashboardTls::Automatic);
        let ip = AccessConfig::from_request(
            request(AccessMode::Ip, "192.0.2.10", Some(8443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap()
        .dashboard_site(None);
        assert_eq!(ip.address, "https://192.0.2.10:8443");
        assert_eq!(ip.tls, DashboardTls::Internal);
    }

    #[test]
    fn the_default_upstream_is_configurable() {
        let configured = AccessConfig::from_request(
            request(AccessMode::Domain, "server.example.com", None),
            "127.0.0.1:8080",
        )
        .unwrap();
        assert_eq!(configured.dashboard_upstream, "127.0.0.1:8080");
        let mut explicit = request(AccessMode::Domain, "server.example.com", None);
        explicit.dashboard_upstream = Some("127.0.0.1:9000".into());
        let explicit = AccessConfig::from_request(explicit, "127.0.0.1:8080").unwrap();
        assert_eq!(explicit.dashboard_upstream, "127.0.0.1:9000");
    }

    #[test]
    fn an_unknown_mode_reads_as_no_configuration_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.json");
        let future = r#"{"schema": 2, "compat": 1, "mode": "onion", "hostname": "x.onion"}"#;
        fs::write(&path, future).unwrap();
        assert_eq!(AccessConfig::load(&path).unwrap(), None);
        assert_eq!(fs::read_to_string(&path).unwrap(), future);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.json");
        let mut config = AccessConfig::from_request(
            request(AccessMode::Domain, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        config.save(&path).unwrap();
        assert_eq!(AccessConfig::load(&path).unwrap().unwrap(), config);
    }
}
