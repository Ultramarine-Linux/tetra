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
//! obtains certificates automatically, with the HTTP-01 challenge by default
//! or DNS-01 through one of terra-caddy's DNS provider modules
//! ([`super::dns`]). For `*.ts.net` names Caddy asks tailscaled instead,
//! which `remote_access.tailscale_up` permits and forwards the tailnet (and,
//! with Funnel, the internet) to Caddy for. DNS credentials are never stored here. **IP mode** serves the dashboard on an
//! IP address with Caddy's internal CA. Browsers do not allow WebAuthn on IP
//! addresses, so passkeys are unavailable in IP mode.
//!
//! This lives in its own file rather than `/etc/tetra/tetra.json` because that
//! file is parsed with `deny_unknown_fields`, and a rolled-back Tetra would
//! refuse a config containing a new section.

use std::net::IpAddr;

use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::Url};

use crate::prelude::*;

use super::{
    dns::{self, DnsCredentials, DnsProvider},
    store::{self, Extra, Header, Record, Tolerant},
};

/// Where the dashboard container listens unless `tetra agent-serve
/// --dashboard-upstream` or `access.set` says otherwise. To be confirmed
/// against the dashboard Quadlet's published port.
pub const DEFAULT_DASHBOARD_UPSTREAM: &str = "127.0.0.1:3972";
/// Relying party name shown by browsers and authenticators.
pub const RP_NAME: &str = "Ultramarine Server";
/// The default HTTPS port, which origins leave out.
pub const HTTPS_PORT: u16 = 443;
/// Port browsers use for the OOBE's Caddy site.
pub const SETUP_PORT: u16 = 6623;
/// Port the OOBE listens on (loopback only), behind its Caddy site.
pub const SETUP_UPSTREAM_PORT: u16 = 6624;
/// Ports the dashboard may not use: none, plain HTTP (Caddy would serve
/// HTTP there while the origin says `https`), Caddy's admin endpoint, and
/// the OOBE's site and the OOBE itself (Caddy listens on every address, so
/// it would collide with a loopback listener too). The dashboard's upstream
/// may not use them either, nor may the site use the upstream's port; see
/// [`AccessConfig::from_request`].
const RESERVED_PORTS: [u16; 5] = [0, 80, 2019, SETUP_PORT, SETUP_UPSTREAM_PORT];

/// Fails when `port` (named `what` in the error) is in [`RESERVED_PORTS`].
fn ensure_unreserved(what: &str, port: u16) -> Result<()> {
    ensure!(
        !RESERVED_PORTS.contains(&port),
        "{what} {port} is reserved; ports 0, 80, 2019 (Caddy's admin endpoint), \
         {SETUP_PORT} (the setup site) and {SETUP_UPSTREAM_PORT} (the setup) cannot \
         serve the dashboard"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// A DNS name (custom domain or Tailscale `ts.net`), with automatic HTTPS.
    Domain,
    /// An IP address, with Caddy's internal CA. No passkeys.
    Ip,
}

/// How Caddy proves control of the domain to the ACME CA.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcmeChallenge {
    /// Caddy answers on port 80 (and TLS-ALPN on 443).
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// Caddy creates a TXT record through the DNS provider's API.
    #[serde(rename = "dns-01")]
    Dns01,
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
    /// Always `http-01` in IP mode, where Caddy uses its internal CA.
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// The DNS provider for `dns-01`. Its credentials are sealed separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_provider: Option<DnsProvider>,
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

/// `access.set` parameters. `Debug` leaves out the credentials' values.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    pub mode: AccessMode,
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub dashboard_upstream: Option<String>,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// Required with `dns-01`.
    #[serde(default)]
    pub dns_provider: Option<DnsProvider>,
    /// With `dns-01`: the provider's credentials. May be left out to keep
    /// the ones already stored for the same provider.
    #[serde(default)]
    pub dns_credentials: Option<DnsCredentials>,
}

impl AccessConfig {
    /// Validate and normalize a request, including its DNS credentials,
    /// which are not part of the result. `default_upstream` is used when the
    /// request does not name the dashboard's address.
    ///
    /// # Errors
    /// Fails when the hostname does not match the mode or is not a valid
    /// name or address, or the DNS settings do not match the challenge and
    /// provider.
    pub fn from_request(request: &AccessRequest, default_upstream: &str) -> Result<Self> {
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
        match request.challenge {
            AcmeChallenge::Http01 => ensure!(
                request.dns_provider.is_none() && request.dns_credentials.is_none(),
                "dns_provider and dns_credentials are only used with the dns-01 challenge"
            ),
            AcmeChallenge::Dns01 => {
                ensure!(
                    request.mode == AccessMode::Domain,
                    "the dns-01 challenge needs domain mode; IP mode uses Caddy's internal CA"
                );
                ensure!(
                    !is_tailnet_name(&hostname),
                    "`{hostname}` is a Tailscale name; Caddy gets its certificate from \
                     tailscaled, so use the http-01 challenge"
                );
                let provider = request
                    .dns_provider
                    .context("dns_provider is required with the dns-01 challenge")?;
                if let Some(credentials) = &request.dns_credentials {
                    dns::validate(provider, credentials)?;
                }
            }
        }
        let upstream = request
            .dashboard_upstream
            .as_deref()
            .unwrap_or(default_upstream)
            .trim()
            .to_owned();
        ensure!(
            upstream.contains(':') && !upstream.contains(char::is_whitespace),
            "dashboard_upstream must be a host:port address"
        );
        if let Some(port) = request.port {
            ensure_unreserved("port", port)?;
        }
        let upstream_port = upstream
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok());
        // Caddy (or the setup) listens there, not the dashboard.
        if let Some(upstream_port) = upstream_port {
            ensure_unreserved("dashboard_upstream port", upstream_port)?;
        }
        // Caddy must not proxy the dashboard's site to itself.
        let port = request.port.unwrap_or(HTTPS_PORT);
        ensure!(
            upstream_port != Some(port),
            "port {port} is reserved; the dashboard may listen on it ({upstream})"
        );
        Ok(Self {
            header: Header::default(),
            mode: request.mode,
            hostname,
            port: request.port.filter(|port| *port != HTTPS_PORT),
            dashboard_upstream: upstream,
            challenge: request.challenge,
            dns_provider: request.dns_provider,
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

    /// The dashboard's origin as browsers send it: `https://<host>[:port]`,
    /// IPv6 addresses bracketed, no trailing slash. This is the dashboard's
    /// `ORIGIN` and the URL the OOBE sends people to.
    ///
    /// # Errors
    /// Fails only for a hostname that is not a valid URL host.
    pub fn origin_string(&self) -> Result<String> {
        Ok(self.origin()?.origin().ascii_serialization())
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
    /// launcher's public page from `public_root` when given. `dns` holds the
    /// credentials for `dns-01`; only the keys and settings are used, secrets
    /// become environment placeholders.
    ///
    /// # Errors
    /// Fails when `dns-01` is configured without credentials.
    #[cfg(feature = "reverse-proxy")]
    pub fn dashboard_site(
        &self,
        public_root: Option<&Path>,
        dns: Option<&DnsCredentials>,
    ) -> Result<crate::agent::modules::reverse_proxy::DashboardSite> {
        use crate::agent::modules::reverse_proxy::{DashboardSite, DashboardTls};
        let port = self.port.map(|port| format!(":{port}")).unwrap_or_default();
        Ok(match self.mode {
            AccessMode::Domain => DashboardSite {
                address: format!("{}{port}", self.hostname),
                tls: match (self.challenge, self.dns_provider) {
                    (AcmeChallenge::Dns01, Some(provider)) => DashboardTls::Dns {
                        provider: provider.name(),
                        fields: dns::caddy_fields(
                            provider,
                            dns.context("dns-01 needs the DNS provider's credentials")?,
                        ),
                    },
                    _ => DashboardTls::Automatic,
                },
                upstream: self.dashboard_upstream.clone(),
                public_root: public_root.map(Path::to_path_buf),
            },
            AccessMode::Ip => DashboardSite {
                address: format!("https://{}{port}", self.url_host()),
                tls: DashboardTls::Internal,
                upstream: self.dashboard_upstream.clone(),
                public_root: public_root.map(Path::to_path_buf),
            },
        })
    }
}

/// Whether `name` is a Tailscale `MagicDNS` name, whose certificate Caddy
/// gets from tailscaled (Caddy treats every `*.ts.net` name this way).
fn is_tailnet_name(name: &str) -> bool {
    name.ends_with(".ts.net")
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
            challenge: AcmeChallenge::Http01,
            dns_provider: None,
            dns_credentials: None,
        }
    }

    #[test]
    fn domain_mode_has_an_origin_and_passkeys() {
        let config = AccessConfig::from_request(
            &request(AccessMode::Domain, "Server.Example.com.", None),
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
            &request(AccessMode::Domain, "server.tail1234.ts.net", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert!(config.passkeys_available());
        #[cfg(feature = "reverse-proxy")]
        assert_eq!(
            config.dashboard_site(None, None).unwrap().tls,
            crate::agent::modules::reverse_proxy::DashboardTls::Automatic
        );
        let mut dns = request(AccessMode::Domain, "server.tail1234.ts.net", None);
        dns.challenge = AcmeChallenge::Dns01;
        dns.dns_provider = Some(DnsProvider::Cloudflare);
        let error = AccessConfig::from_request(&dns, DEFAULT_DASHBOARD_UPSTREAM).unwrap_err();
        assert!(error.to_string().contains("Tailscale name"), "{error}");
    }

    #[test]
    fn non_default_ports_are_part_of_the_origin() {
        let config = AccessConfig::from_request(
            &request(AccessMode::Domain, "server.example.com", Some(8443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(
            config.origin().unwrap().as_str(),
            "https://server.example.com:8443/"
        );
        let default = AccessConfig::from_request(
            &request(AccessMode::Domain, "server.example.com", Some(443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(default.port, None);
    }

    #[test]
    fn reserved_ports_are_refused() {
        for port in [0, 80, 2019, SETUP_PORT, SETUP_UPSTREAM_PORT, 3972] {
            let error = AccessConfig::from_request(
                &request(AccessMode::Domain, "server.example.com", Some(port)),
                DEFAULT_DASHBOARD_UPSTREAM,
            )
            .unwrap_err();
            assert!(error.to_string().contains("reserved"), "{port}: {error}");
        }
        // The dashboard's port is the one it listens on, wherever that is.
        let mut moved = request(AccessMode::Domain, "server.example.com", Some(8443));
        moved.dashboard_upstream = Some("127.0.0.1:8443".into());
        let error = AccessConfig::from_request(&moved, DEFAULT_DASHBOARD_UPSTREAM).unwrap_err();
        assert!(error.to_string().contains("reserved"), "{error}");
        let error = AccessConfig::from_request(
            &request(AccessMode::Domain, "server.example.com", Some(8443)),
            "[::1]:8443",
        )
        .unwrap_err();
        assert!(error.to_string().contains("reserved"), "{error}");
        moved.dashboard_upstream = None;
        AccessConfig::from_request(&moved, DEFAULT_DASHBOARD_UPSTREAM).unwrap();
        // Nor may the dashboard listen where Caddy or the setup does.
        for port in [0, 80, 2019, SETUP_PORT, SETUP_UPSTREAM_PORT] {
            moved.dashboard_upstream = Some(format!("127.0.0.1:{port}"));
            let error = AccessConfig::from_request(&moved, DEFAULT_DASHBOARD_UPSTREAM).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("dashboard_upstream port {port} is reserved")),
                "{error}"
            );
        }
        moved.dashboard_upstream = None;
        // With the port omitted the site is on 443.
        let mut default_port = request(AccessMode::Domain, "server.example.com", None);
        default_port.dashboard_upstream = Some("127.0.0.1:443".into());
        let error =
            AccessConfig::from_request(&default_port, DEFAULT_DASHBOARD_UPSTREAM).unwrap_err();
        assert!(
            error.to_string().contains("port 443 is reserved"),
            "{error}"
        );
    }

    #[test]
    fn ip_mode_has_no_passkeys() {
        let config = AccessConfig::from_request(
            &request(AccessMode::Ip, "[2001:db8::1]", None),
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
            &request(AccessMode::Domain, "192.0.2.1", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap_err();
        AccessConfig::from_request(
            &request(AccessMode::Ip, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap_err();
        AccessConfig::from_request(
            &request(AccessMode::Domain, "bad name {", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap_err();
    }

    #[cfg(feature = "reverse-proxy")]
    #[test]
    fn builds_dashboard_sites() {
        use crate::agent::modules::reverse_proxy::DashboardTls;
        let domain = AccessConfig::from_request(
            &request(AccessMode::Domain, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap()
        .dashboard_site(None, None)
        .unwrap();
        assert_eq!(domain.address, "server.example.com");
        assert_eq!(domain.tls, DashboardTls::Automatic);
        let ip = AccessConfig::from_request(
            &request(AccessMode::Ip, "192.0.2.10", Some(8443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap()
        .dashboard_site(None, None)
        .unwrap();
        assert_eq!(ip.address, "https://192.0.2.10:8443");
        assert_eq!(ip.tls, DashboardTls::Internal);
    }

    fn dns_request(value: Value) -> AccessRequest {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn dns_01_names_a_provider_and_stores_no_credentials() {
        let request = dns_request(serde_json::json!({
            "mode": "domain",
            "hostname": "server.example.com",
            "challenge": "dns-01",
            "dns_provider": "cloudflare",
            "dns_credentials": {"api_token": "s3cret-token"}
        }));
        assert!(!format!("{request:?}").contains("s3cret-token"));
        let config = AccessConfig::from_request(&request, DEFAULT_DASHBOARD_UPSTREAM).unwrap();
        assert_eq!(config.challenge, AcmeChallenge::Dns01);
        assert_eq!(config.dns_provider, Some(DnsProvider::Cloudflare));
        let stored = serde_json::to_string(&config).unwrap();
        assert!(stored.contains("\"challenge\":\"dns-01\""), "{stored}");
        assert!(!stored.contains("s3cret-token"));

        #[cfg(feature = "reverse-proxy")]
        {
            use crate::agent::modules::reverse_proxy::DashboardTls;
            config.dashboard_site(None, None).unwrap_err();
            let site = config
                .dashboard_site(None, request.dns_credentials.as_ref())
                .unwrap();
            assert_eq!(
                site.tls,
                DashboardTls::Dns {
                    provider: "cloudflare",
                    fields: vec![(
                        "api_token",
                        dns::DnsValue::Env("TETRA_DNS_API_TOKEN".into())
                    )],
                }
            );
        }
    }

    #[test]
    fn dns_01_is_validated() {
        for body in [
            // No provider.
            serde_json::json!({"mode": "domain", "hostname": "a.example.com", "challenge": "dns-01"}),
            // IP mode has no ACME.
            serde_json::json!({"mode": "ip", "hostname": "192.0.2.1", "challenge": "dns-01", "dns_provider": "desec"}),
            // Credentials for the wrong provider.
            serde_json::json!({"mode": "domain", "hostname": "a.example.com", "challenge": "dns-01",
                "dns_provider": "desec", "dns_credentials": {"api_token": "x"}}),
            // No credentials at all, or an oversized secret.
            serde_json::json!({"mode": "domain", "hostname": "a.example.com", "challenge": "dns-01",
                "dns_provider": "cloudflare", "dns_credentials": {}}),
            serde_json::json!({"mode": "domain", "hostname": "a.example.com", "challenge": "dns-01",
                "dns_provider": "cloudflare", "dns_credentials": {"api_token": "x".repeat(5000)}}),
            // DNS settings without dns-01.
            serde_json::json!({"mode": "domain", "hostname": "a.example.com", "dns_provider": "desec"}),
            serde_json::json!({"mode": "domain", "hostname": "a.example.com",
                "dns_credentials": {"api_token": "x"}}),
        ] {
            AccessConfig::from_request(&dns_request(body), DEFAULT_DASHBOARD_UPSTREAM).unwrap_err();
        }
        serde_json::from_value::<AccessRequest>(serde_json::json!({
            "mode": "domain", "hostname": "a.example.com", "challenge": "tls-alpn-01"
        }))
        .unwrap_err();
    }

    #[test]
    fn origin_strings_have_no_trailing_slash() {
        let ip = AccessConfig::from_request(
            &request(AccessMode::Ip, "2001:db8::1", Some(8443)),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(ip.origin_string().unwrap(), "https://[2001:db8::1]:8443");
        let domain = AccessConfig::from_request(
            &request(AccessMode::Domain, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        assert_eq!(
            domain.origin_string().unwrap(),
            "https://server.example.com"
        );
    }

    #[test]
    fn files_from_before_dns_01_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.json");
        fs::write(
            &path,
            r#"{"schema": 1, "compat": 1, "mode": "domain", "hostname": "server.example.com"}"#,
        )
        .unwrap();
        let config = AccessConfig::load(&path).unwrap().unwrap();
        assert_eq!(config.challenge, AcmeChallenge::Http01);
        assert_eq!(config.dns_provider, None);
    }

    #[test]
    fn the_default_upstream_is_configurable() {
        let configured = AccessConfig::from_request(
            &request(AccessMode::Domain, "server.example.com", None),
            "127.0.0.1:8080",
        )
        .unwrap();
        assert_eq!(configured.dashboard_upstream, "127.0.0.1:8080");
        let mut explicit = request(AccessMode::Domain, "server.example.com", None);
        explicit.dashboard_upstream = Some("127.0.0.1:9000".into());
        let explicit = AccessConfig::from_request(&explicit, "127.0.0.1:8080").unwrap();
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
            &request(AccessMode::Domain, "server.example.com", None),
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap();
        config.save(&path).unwrap();
        assert_eq!(AccessConfig::load(&path).unwrap().unwrap(), config);
    }
}
