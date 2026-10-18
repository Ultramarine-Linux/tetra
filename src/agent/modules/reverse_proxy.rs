//! Caddy reverse proxy site management.
//!
//! Manages per-site Caddy snippet files under a managed directory so the
//! Ultramarine Server dashboard can provision reverse proxies for hosted
//! services (e.g. point `app.example.com` at a container's `127.0.0.1:8080`)
//! without editing the main Caddyfile by hand. Each site is a small
//! `*.caddy` file with a `reverse_proxy` block; the main Caddyfile is
//! expected to `import` the managed directory.
//!
//! Registered behind the `reverse-proxy` cargo feature. Mutating actions
//! (`write`, `delete`) accept `dry_run` and an optional `reload` flag that
//! triggers `systemctl reload caddy.service` after the change.

use crate::prelude::*;

use crate::agent::module_support::safe_join;

/// Agent module that manages Caddy reverse proxy snippets.
///
/// Stateless: all persisted state lives as `*.caddy` files under the
/// configured `config_dir`, with site metadata embedded in a header comment
/// so the module can list and round-trip sites without a separate database.
#[derive(Clone, Copy, Debug)]
pub struct ReverseProxyModule;

/// Static descriptor published via the shared `capabilities` and `plan`
/// actions; one source of truth for the module's name, feature gate, and
/// supported actions.
const INFO: ModuleInfo = ModuleInfo {
    name: "reverse_proxy",
    feature: "reverse-proxy",
    description: "Manage Caddy reverse proxy site snippets for hosted services.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "list",
        "render",
        "write",
        "delete",
        "reload",
    ],
    privileged_actions: &["write", "delete", "reload"],
};

/// Directory where managed site snippets live. Overridable per request via
/// `config_dir` (used by tests and deployments that keep Caddy config
/// elsewhere). The main Caddyfile is expected to `import` this directory.
const DEFAULT_CONFIG_DIR: &str = "/etc/caddy/tetra-sites";
/// Sentinel first line written to every managed file. `list_sites` uses this
/// to distinguish Tetra-managed snippets from any other `*.caddy` files the
/// operator may have placed in the same directory, so we never touch files
/// we didn't write.
const MANAGED_HEADER: &str = "# Managed by Tetra reverse_proxy";

fn default_config_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR)
}

/// In-memory and on-disk representation of a managed site. Serialized as
/// JSON into a `# tetra: ...` comment header in the snippet so `list_sites`
/// can recover the original parameters without re-parsing the Caddy block.
#[derive(Debug, Serialize, Deserialize)]
struct SiteMetadata {
    domain: String,
    upstream: String,
    tls: bool,
}
impl SiteMetadata {
    fn new(domain: &str, upstream: &str, tls: bool) -> Result<Self> {
        Ok(Self {
            domain: validate_domain(domain)?,
            upstream: validate_upstream(upstream)?,
            tls,
        })
    }

    /// Render a single site snippet.
    ///
    /// The `# tetra: {metadata}` line embeds `SiteMetadata` as JSON so
    /// `list_sites` can round-trip the original parameters. TLS off uses an
    /// `http://` site address, which serves the site over plain HTTP without
    /// provisioning a certificate. (`auto_https` is a global option and Caddy
    /// rejects it inside a site block.)
    fn render(&self) -> Result<String> {
        let metadata = serde_json::to_string(self)?;
        let scheme = if self.tls { "" } else { "http://" };
        Ok(format!(
            "{MANAGED_HEADER}\n# tetra: {metadata}\n{scheme}{} {{\n\treverse_proxy {}\n}}\n",
            self.domain, self.upstream
        ))
    }
}

impl Mod for ReverseProxyModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    List {
        #[serde(default = "default_config_dir")]
        config_dir: PathBuf,
    } => Ok(jsonf! { payload.config_dir, "sites": list_sites(&payload.config_dir)? }),
    Render {
        #[serde(default = "default_config_dir")]
        config_dir: PathBuf,
        domain: String,
        upstream: String,
        #[serde(default = "default_tls")]
        tls: bool,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        reload: bool,
    } => {
        let site = SiteMetadata::new(&payload.domain, &payload.upstream, payload.tls)?;
        Ok(jsonf! {
            payload.config_dir,
            "filename": site_filename(&site.domain),
            "contents": site.render()?,
            site,
            payload.dry_run,
            payload.reload,
        })
    },
    Write {
        #[serde(default = "default_config_dir")]
        config_dir: PathBuf,
        domain: String,
        upstream: String,
        #[serde(default = "default_tls")]
        tls: bool,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        reload: bool,
    } => {
        let config_dir = &payload.config_dir;
        let site = SiteMetadata::new(&payload.domain, &payload.upstream, payload.tls)?;
        let filename = site_filename(&site.domain);
        let path = safe_join(config_dir, &filename)?;
        let contents = site.render()?;

        if !payload.dry_run {
            fs::create_dir_all(config_dir)
                .with_context(|| format!("failed to create `{}`", config_dir.display()))?;
            fs::write(&path, &contents)
                .with_context(|| format!("failed to write `{}`", path.display()))?;
        }

        let (reload, reload_error) = if payload.reload {
            match reload_caddy("write", payload.dry_run, user) {
                Ok(result) => (Some(result), None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, None)
        };

        Ok(jsonf! {
            config_dir, filename, path, contents, site,
            "written": !payload.dry_run,
            payload.dry_run, reload, reload_error,
        })
    },
    Delete {
        #[serde(default = "default_config_dir")]
        config_dir: PathBuf,
        domain: String,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        reload: bool,
    } => {
        let config_dir = &payload.config_dir;
        let domain = validate_domain(&payload.domain)?;
        let filename = site_filename(&domain);
        let path = safe_join(config_dir, &filename)?;

        if !payload.dry_run && path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete `{}`", path.display()))?;
        }

        let (reload, reload_error) = if payload.reload {
            match reload_caddy("delete", payload.dry_run, user) {
                Ok(result) => (Some(result), None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, None)
        };

        Ok(jsonf! {
            config_dir, filename, path,
            "deleted": !payload.dry_run,
            payload.dry_run, reload, reload_error,
        })
    },
    Reload {
        #[serde(default)]
        dry_run: bool,
    } => reload_caddy("reload", payload.dry_run, user)
});

/// Serde default for `tls`. Caddy auto-provisions HTTPS, so TLS is the
/// safe default; callers must explicitly opt out.
const fn default_tls() -> bool {
    true
}

/// Normalize and validate a DNS domain for use as a Caddy site label.
///
/// Lowercases and strips the trailing dot (FQDN form), then enforces RFC
/// length limits and allowed characters. This is primarily a safety check:
/// the domain is interpolated into a Caddy block, so rejecting `/`, `:`,
/// and non-DNS characters prevents Caddy config injection.
fn validate_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        bail!("domain is required");
    }
    if domain.len() > 253
        || domain.contains('/')
        || domain.contains(':')
        || !domain
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')
        || domain.split('.').any(|part| {
            part.is_empty() || part.starts_with('-') || part.ends_with('-') || part.len() > 63
        })
    {
        bail!("invalid domain `{domain}`");
    }

    Ok(domain)
}

/// Validate an upstream address such as `127.0.0.1:8080`.
///
/// As with the domain, the upstream is interpolated into a Caddy block, so
/// newlines and `{`/`}` are rejected to prevent block injection. Requiring
/// a `:` catches the common mistake of omitting the port.
fn validate_upstream(upstream: &str) -> Result<String> {
    let upstream = upstream.trim();
    if upstream.is_empty() {
        bail!("upstream is required");
    }
    if upstream.contains('\n')
        || upstream.contains('\r')
        || upstream.contains('{')
        || upstream.contains('}')
    {
        bail!("invalid upstream `{upstream}`");
    }
    if !upstream.contains(':') {
        bail!("upstream must include a host and port, such as 127.0.0.1:8080");
    }

    Ok(upstream.to_owned())
}

/// Map a (validated) domain to a safe on-disk snippet filename.
///
/// `*` (wildcard site labels) becomes `wildcard` and `.` becomes `_`, so
/// `*.example.com` -> `wildcard_example_com.caddy`. The domain is already
/// validated to contain only `[a-z0-9-.]`, so no further escaping is needed.
fn site_filename(domain: &str) -> String {
    format!(
        "{}.caddy",
        domain.replace('*', "wildcard").replace('.', "_")
    )
}

/// List Tetra-managed sites in `config_dir`.
///
/// Skips any `*.caddy` file that doesn't start with `MANAGED_HEADER`, so
/// operator-authored files in the same directory are neither reported nor
/// touched. Metadata is recovered from the `# tetra:` comment line; files
/// without a parseable header are silently ignored. Results are sorted by
/// domain for stable dashboard output.
fn list_sites(config_dir: &Path) -> Result<Vec<Value>> {
    let mut sites = Vec::new();
    if !config_dir.exists() {
        return Ok(sites);
    }

    for entry in fs::read_dir(config_dir)
        .with_context(|| format!("failed to read `{}`", config_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("caddy") {
            continue;
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read `{}`", path.display()))?;
        if !contents.starts_with(MANAGED_HEADER) {
            continue;
        }

        let metadata = contents
            .lines()
            .find_map(|line| line.strip_prefix("# tetra: "))
            .and_then(|raw| serde_json::from_str::<SiteMetadata>(raw).ok());
        if let Some(site) = metadata {
            sites.push(jsonf! {
                "filename": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                path, site.domain, site.upstream, site.tls,
            });
        }
    }

    sites.sort_by(|left, right| left["domain"].as_str().cmp(&right["domain"].as_str()));
    Ok(sites)
}

/// Reload Caddy via systemd so new or removed sites take effect without
/// restarting (which would drop active connections). Dry runs report the
/// command that would run without invoking systemctl.
fn reload_caddy(action: &str, dry_run: bool, user: Option<&str>) -> Result<Value> {
    crate::cmd!((dry_run) { &INFO, action, user } "systemctl" ["reload", "caddy.service"] json)
}

/// Filename of the dashboard's own site.
///
/// Written by Tetra's `access.set` operation rather than by a module action.
/// It does not start with the `MANAGED_HEADER` line, so `list` (which reports
/// app sites) skips it and `delete` cannot remove it. The `00-` prefix keeps
/// it first in the import order.
pub const DASHBOARD_SITE_FILE: &str = "00-ultramarine-dashboard.caddy";
const DASHBOARD_HEADER: &str = "# Managed by Tetra access.set: Ultramarine Server dashboard";

/// How the dashboard site gets its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTls {
    /// Caddy's automatic HTTPS (Let's Encrypt, or Tailscale for `ts.net`).
    Automatic,
    /// Caddy's local CA (`tls internal`), for IP mode.
    Internal,
}

/// The dashboard's site block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardSite {
    /// Caddy site address, such as `server.example.com`,
    /// `https://192.0.2.10` or `https://[2001:db8::1]:8443`.
    pub address: String,
    pub tls: DashboardTls,
    /// Where the dashboard container listens, such as `127.0.0.1:3000`.
    pub upstream: String,
}

impl DashboardSite {
    /// Render the site file.
    ///
    /// # Errors
    /// Fails when the address or upstream could inject Caddy syntax.
    pub fn render(&self) -> Result<String> {
        ensure!(
            !self.address.is_empty()
                && self.address.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '/' | '[' | ']')
                }),
            "invalid dashboard site address `{}`",
            self.address
        );
        let upstream = validate_upstream(&self.upstream)?;
        let tls = match self.tls {
            DashboardTls::Automatic => "",
            DashboardTls::Internal => "\ttls internal\n",
        };
        Ok(format!(
            "{DASHBOARD_HEADER}\n{} {{\n{tls}\treverse_proxy {upstream}\n}}\n",
            self.address
        ))
    }
}

/// Write the dashboard site into `config_dir`, replacing any previous one,
/// and optionally reload Caddy.
///
/// # Errors
/// Fails when the site is invalid or cannot be written. A failed reload is
/// reported in the result instead, like the `write` action does.
pub fn write_dashboard_site(
    config_dir: &Path,
    site: &DashboardSite,
    dry_run: bool,
    reload: bool,
) -> Result<Value> {
    let contents = site.render()?;
    let path = safe_join(config_dir, DASHBOARD_SITE_FILE)?;
    if !dry_run {
        fs::create_dir_all(config_dir)
            .with_context(|| format!("failed to create `{}`", config_dir.display()))?;
        fs::write(&path, &contents)
            .with_context(|| format!("failed to write `{}`", path.display()))?;
    }
    let (reload, reload_error) = if reload {
        match reload_caddy("write", dry_run, None) {
            Ok(result) => (Some(result), None),
            Err(error) => (None, Some(error.to_string())),
        }
    } else {
        (None, None)
    };
    Ok(jsonf! { path, contents, "written": !dry_run, dry_run, reload, reload_error })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_caddy_site() {
        let response = Render {
            config_dir: default_config_dir(),
            domain: "app.example.com".into(),
            upstream: "127.0.0.1:8080".into(),
            tls: true,
            dry_run: false,
            reload: false,
        }
        .handle(None)
        .unwrap();

        assert!(
            response["contents"]
                .as_str()
                .unwrap()
                .contains("app.example.com")
        );
        assert!(
            response["contents"]
                .as_str()
                .unwrap()
                .contains("reverse_proxy 127.0.0.1:8080")
        );
    }

    #[test]
    fn renders_plain_http_site_without_auto_https() {
        let site = SiteMetadata::new("app.example.com", "127.0.0.1:8080", false).unwrap();
        let contents = site.render().unwrap();
        let site_block = contents
            .lines()
            .find(|line| !line.starts_with('#'))
            .unwrap();

        assert!(site_block.starts_with("http://app.example.com "));
        assert!(!contents.contains("auto_https"));
    }

    #[test]
    fn renders_tls_site_with_bare_domain() {
        let site = SiteMetadata::new("app.example.com", "127.0.0.1:8080", true).unwrap();
        let contents = site.render().unwrap();

        assert!(contents.contains("\napp.example.com {\n"));
        assert!(!contents.contains("http://"));
    }

    #[test]
    fn renders_dashboard_sites_for_domain_and_ip_mode() {
        let domain = DashboardSite {
            address: "server.example.com".into(),
            tls: DashboardTls::Automatic,
            upstream: "127.0.0.1:3000".into(),
        };
        assert_eq!(
            domain.render().unwrap(),
            format!("{DASHBOARD_HEADER}\nserver.example.com {{\n\treverse_proxy 127.0.0.1:3000\n}}\n")
        );
        let ip = DashboardSite {
            address: "https://[2001:db8::1]".into(),
            tls: DashboardTls::Internal,
            upstream: "127.0.0.1:3000".into(),
        };
        assert!(ip.render().unwrap().contains("https://[2001:db8::1] {\n\ttls internal\n"));
        let injected = DashboardSite {
            address: "evil.example.com {\n".into(),
            ..domain
        };
        injected.render().unwrap_err();
    }

    #[test]
    fn dashboard_site_is_not_listed_as_an_app_site() {
        let dir = tempfile::tempdir().unwrap();
        let site = DashboardSite {
            address: "server.example.com".into(),
            tls: DashboardTls::Automatic,
            upstream: "127.0.0.1:3000".into(),
        };
        write_dashboard_site(dir.path(), &site, false, false).unwrap();
        assert!(dir.path().join(DASHBOARD_SITE_FILE).exists());
        assert_eq!(list_sites(dir.path()).unwrap().len(), 0);
    }

    #[test]
    fn dry_run_write_does_not_create_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("demo_example_com.caddy");
        let response = Write {
            config_dir: dir.path().to_path_buf(),
            domain: "demo.example.com".into(),
            upstream: "127.0.0.1:3000".into(),
            tls: true,
            dry_run: true,
            reload: false,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["written"], false);
        assert!(!path.exists());
    }
}
