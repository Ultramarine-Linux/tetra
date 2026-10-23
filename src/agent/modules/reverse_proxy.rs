//! Caddy reverse proxy site management.
//!
//! Manages per-site Caddy snippet files under a managed directory so the
//! Ultramarine Server dashboard can provision reverse proxies for hosted
//! services (e.g. point `app.example.com` at a container's `127.0.0.1:8080`)
//! without editing the main Caddyfile by hand. Each site is a small
//! `*.caddyfile` file with a `reverse_proxy` block in
//! `/etc/caddy/Caddyfile.d`, which terra-caddy's default Caddyfile already
//! imports (`import Caddyfile.d/*.caddyfile`). Operator files in the same
//! directory are left alone: Tetra only rewrites files it wrote. Sites that
//! released versions wrote to [`LEGACY_CONFIG_DIR`] are moved here when the
//! agent starts ([`migrate_legacy_sites`]).
//!
//! The same directory holds two sites Tetra writes itself rather than
//! through module actions: the dashboard's site (`access.set`) and, until
//! setup completes, the OOBE's site on port 6623.
//!
//! Registered behind the `reverse-proxy` cargo feature. Mutating actions
//! (`write`, `delete`) accept `dry_run` and an optional `reload` flag that
//! triggers `systemctl reload caddy.service` after the change.

use crate::prelude::*;

use crate::agent::module_support::safe_join;
pub use crate::auth::dns::DnsValue;

/// Agent module that manages Caddy reverse proxy snippets.
///
/// Stateless: all persisted state lives as `*.caddyfile` files under the
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

/// Directory where managed site snippets live: terra-caddy's drop-in
/// directory.
///
/// Overridable per request via `config_dir` (administrators only; used by
/// tests and deployments that keep Caddy config elsewhere).
pub const DEFAULT_CONFIG_DIR: &str = crate::auth::service::CADDY_SITES_DIR;
/// Extension terra-caddy's Caddyfile imports from [`DEFAULT_CONFIG_DIR`].
const SITE_EXTENSION: &str = "caddyfile";
/// Sentinel first line written to every managed file. `list_sites` uses this
/// to distinguish Tetra-managed snippets from any other `*.caddyfile` files the
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
            "filename": site_filename(&site.domain)?,
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
        let filename = site_filename(&site.domain)?;
        let path = safe_join(config_dir, &filename)?;
        ensure_managed(&path)?;
        let contents = site.render()?;

        if !payload.dry_run {
            fs::create_dir_all(config_dir)
                .with_context(|| format!("failed to create `{}`", config_dir.display()))?;
            crate::auth::store::replace(&path, contents.as_bytes(), SITE_MODE)?;
        }
        let (reload, reload_error) = optional_reload(payload.reload, "write", payload.dry_run, user);

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
        let filename = site_filename(&domain)?;
        let path = safe_join(config_dir, &filename)?;
        ensure_managed(&path)?;

        if !payload.dry_run {
            crate::auth::store::remove(&path)?;
        }
        let (reload, reload_error) = optional_reload(payload.reload, "delete", payload.dry_run, user);

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

/// Reload Caddy when asked. A failed reload is reported next to the change
/// (which already happened) rather than failing the action.
fn optional_reload(
    reload: bool,
    action: &str,
    dry_run: bool,
    user: Option<&str>,
) -> (Option<Value>, Option<String>) {
    if !reload {
        return (None, None);
    }
    match reload_caddy(action, dry_run, user) {
        Ok(result) => (Some(result), None),
        Err(error) => (None, Some(error.to_string())),
    }
}

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
    if !crate::auth::access::is_dns_name(&domain) {
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
    // One address only: whitespace would add more upstreams to the
    // `reverse_proxy` directive, and braces or newlines more directives.
    if !upstream
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']' | '/'))
    {
        bail!("invalid upstream `{upstream}`");
    }
    // `[scheme://]host:port[/...]`: the port is required, and may not be one
    // that would expose Caddy's admin API or the OOBE to anyone who can
    // reach the new site (`reverse_proxy.write` is grantable).
    let authority = upstream.split_once("://").map_or(upstream, |(_, rest)| rest);
    let authority = authority.split('/').next().unwrap_or_default();
    let port = authority
        .rsplit_once(':')
        .and_then(|(host, port)| (!host.is_empty()).then_some(port))
        .and_then(|port| port.parse::<u16>().ok())
        .context("upstream must include a host and port, such as 127.0.0.1:8080")?;
    ensure!(
        ![
            crate::auth::access::CADDY_ADMIN_PORT,
            crate::auth::access::SETUP_UPSTREAM_PORT
        ]
        .contains(&port),
        "upstream port {port} is reserved for Caddy's admin API or the setup"
    );

    Ok(upstream.to_owned())
}

/// Map a (validated) domain to a safe on-disk snippet filename.
///
/// `*` (wildcard site labels) becomes `wildcard` and `.` becomes `_`, so
/// `*.example.com` -> `wildcard_example_com.caddyfile`. The domain is already
/// validated to contain only `[a-z0-9-.]`, so no further escaping is needed.
///
/// A domain whose filename would be one of Tetra's own sites (such as
/// `00-ultramarine-dashboard`) is refused.
fn site_filename(domain: &str) -> Result<String> {
    let filename = format!(
        "{}.{SITE_EXTENSION}",
        domain.replace('*', "wildcard").replace('.', "_")
    );
    ensure!(
        filename != DASHBOARD_SITE_FILE && filename != SETUP_SITE_FILE,
        "`{domain}` is reserved for Tetra's own sites"
    );
    Ok(filename)
}

/// Refuse to touch an existing file that Tetra's `write` action did not
/// create (operator files, the dashboard site).
fn ensure_managed(path: &Path) -> Result<()> {
    match fs::read_to_string(path) {
        Ok(contents) if !contents.starts_with(MANAGED_HEADER) => bail!(
            "`{}` is not managed by Tetra reverse_proxy; refusing to change it",
            path.display()
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to read `{}`", path.display())),
    }
}

/// List Tetra-managed sites in `config_dir`.
///
/// Skips any `*.caddyfile` file that doesn't start with `MANAGED_HEADER`, so
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
        if path.extension().and_then(|ext| ext.to_str()) != Some(SITE_EXTENSION) {
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

/// Where released versions (up to 0.2.3) kept app sites, as `<name>.caddy`.
pub const LEGACY_CONFIG_DIR: &str = "/etc/caddy/tetra-sites";

/// Move the app sites `write` left in `legacy_dir` to `config_dir`.
///
/// `tetra agent-serve` passes [`LEGACY_CONFIG_DIR`] and
/// [`DEFAULT_CONFIG_DIR`], the directory `list`, `write`, and `delete` use.
///
/// Released versions kept them in [`LEGACY_CONFIG_DIR`] as `<name>.caddy`;
/// they become `<name>.caddyfile`, which terra-caddy imports. Files Tetra did not write, and ones whose new name
/// is taken or reserved, stay where they are. Returns the files moved.
///
/// # Errors
/// Fails when a directory cannot be read or created or a file moved; the
/// files moved before stay moved.
pub fn migrate_legacy_sites(legacy_dir: &Path, config_dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(legacy_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read `{}`", legacy_dir.display()));
        }
    };
    let mut moved = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let Some(stem) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .filter(|_| path.extension().is_some_and(|ext| ext == "caddy"))
        else {
            continue;
        };
        let filename = format!("{stem}.{SITE_EXTENSION}");
        let target = config_dir.join(&filename);
        let managed = entry.file_type()?.is_file()
            && fs::read_to_string(&path).is_ok_and(|contents| contents.starts_with(MANAGED_HEADER));
        if !managed
            || filename == DASHBOARD_SITE_FILE
            || filename == SETUP_SITE_FILE
            || fs::symlink_metadata(&target).is_ok()
        {
            continue;
        }
        fs::create_dir_all(config_dir)
            .with_context(|| format!("failed to create `{}`", config_dir.display()))?;
        fs::rename(&path, &target)
            .with_context(|| format!("failed to move `{}`", path.display()))?;
        moved.push(target);
    }
    Ok(moved)
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
/// app sites) skips it, and `write` and `delete` refuse its name. The `00-` prefix keeps
/// it first in the import order.
pub const DASHBOARD_SITE_FILE: &str = "00-ultramarine-dashboard.caddyfile";
const DASHBOARD_HEADER: &str = "# Managed by Tetra access.set: Ultramarine Server dashboard";

/// How the dashboard site gets its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardTls {
    /// Caddy's automatic HTTPS (Let's Encrypt, or Tailscale for `ts.net`),
    /// with the HTTP-01 challenge.
    Automatic,
    /// Caddy's local CA (`tls internal`), for IP mode.
    Internal,
    /// Automatic HTTPS with the DNS-01 challenge through a caddy-dns module.
    Dns {
        /// The module, such as `cloudflare`.
        provider: &'static str,
        /// The provider block's settings and secret placeholders; never a
        /// credential.
        fields: Vec<(&'static str, DnsValue)>,
    },
}

/// One `key value` line of a DNS provider block. Keys are lowercase words;
/// secrets become a `{env.NAME}` placeholder and settings a quoted literal
/// that cannot close the quote or a block.
fn render_dns_field(key: &str, value: &DnsValue) -> Result<String> {
    ensure!(
        !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
        "invalid DNS provider key `{key}`"
    );
    let value = match value {
        DnsValue::Env(name) => {
            ensure!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "invalid environment variable for DNS provider key `{key}`"
            );
            format!("{{env.{name}}}")
        }
        DnsValue::Literal(text) => {
            ensure!(
                !text.is_empty()
                    && !text.chars().any(|c| {
                        matches!(c, '"' | '\\' | '{' | '}') || c.is_control() || c.is_whitespace()
                    }),
                "invalid value for DNS provider key `{key}`"
            );
            format!("\"{text}\"")
        }
    };
    Ok(format!("\t\t\t{key} {value}\n"))
}

/// The dashboard's site block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardSite {
    /// Caddy site address, such as `server.example.com`,
    /// `https://192.0.2.10` or `https://[2001:db8::1]:8443`.
    pub address: String,
    pub tls: DashboardTls,
    /// Where the dashboard container listens, such as `127.0.0.1:3972`.
    pub upstream: String,
    /// Directory of the launcher's public page, served under `/public/`
    /// without a login. Tetra removes the page while it is disabled, so the
    /// route then answers 404.
    pub public_root: Option<PathBuf>,
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
        let tls = match &self.tls {
            DashboardTls::Automatic => String::new(),
            DashboardTls::Internal => "\ttls internal\n".to_owned(),
            DashboardTls::Dns { provider, fields } => {
                ensure!(
                    !provider.is_empty() && provider.chars().all(|c| c.is_ascii_alphanumeric()),
                    "invalid DNS provider `{provider}`"
                );
                let mut block = format!("\ttls {{\n\t\tdns {provider} {{\n");
                for (key, value) in fields {
                    block.push_str(&render_dns_field(key, value)?);
                }
                block.push_str("\t\t}\n\t}\n");
                block
            }
        };
        let public = match &self.public_root {
            Some(root) => {
                let root = root.to_str().unwrap_or_default();
                ensure!(
                    root.starts_with('/')
                        && root.chars().all(|ch| {
                            ch.is_ascii_alphanumeric() || matches!(ch, '/' | '-' | '_' | '.')
                        }),
                    "invalid public page directory `{root}`"
                );
                format!(
                    "\tredir /public /public/\n\thandle_path /public/* {{\n\t\troot * {root}\n\t\tfile_server\n\t}}\n"
                )
            }
            None => String::new(),
        };
        Ok(format!(
            "{DASHBOARD_HEADER}\n{} {{\n{tls}{public}\treverse_proxy {upstream}\n}}\n",
            self.address
        ))
    }
}

/// Write the dashboard site, as rendered by [`DashboardSite::render`], into
/// `config_dir`, replacing any previous one. Does not reload Caddy.
///
/// # Errors
/// Fails when the file cannot be written.
pub fn write_dashboard_site(config_dir: &Path, contents: &str) -> Result<Value> {
    let path = safe_join(config_dir, DASHBOARD_SITE_FILE)?;
    let changed = crate::auth::store::replace_if_changed(&path, contents.as_bytes(), SITE_MODE)?;
    Ok(jsonf! { path, contents, changed })
}

/// Mode of the sites Tetra writes itself: Caddy runs as `caddy` and only
/// needs to read them.
const SITE_MODE: u32 = 0o644;

/// Filename of the OOBE's site, written while setup is incomplete.
pub const SETUP_SITE_FILE: &str = "00-ultramarine-setup.caddyfile";
const SETUP_HEADER: &str = "# Managed by Tetra setup: Ultramarine Server setup (OOBE)";
pub use crate::auth::access::{SETUP_PORT, SETUP_UPSTREAM_PORT};

/// The OOBE's site: HTTPS on [`SETUP_PORT`] for any address or name the
/// browser uses, with a certificate from Caddy's internal CA, proxied to the
/// OOBE on port [`SETUP_UPSTREAM_PORT`] of `127.0.0.1`.
///
/// The site has no host, so Caddy cannot know names up front: certificates
/// are issued on demand, which Caddy allows without an `ask` endpoint because
/// only the internal issuer is used. Caddy listens on the port on every
/// address, IPv4 and IPv6 (a dual-stack wildcard socket), and still starts
/// on hosts with IPv6 disabled, so the site does not `bind` explicitly.
///
/// Accepted risk: without `ask`, any client that reaches the port can make
/// Caddy issue (and store under its data directory) an internal certificate
/// for any SNI name it sends. An `ask` endpoint or a `permission` module can
/// only be set in the global options of terra-caddy's main Caddyfile, not in
/// this drop-in, and the server's addresses are not known when this file is
/// written at boot (DHCP, Wi-Fi joined during setup), so they cannot be
/// listed instead. The risk is disk and CPU use, not impersonation: the
/// certificates and their keys never leave Caddy, which serves them only on
/// this port; only the internal CA signs (no public CA is asked); each
/// certificate is small; and the site exists only until setup completes.
#[must_use]
pub fn render_setup_site() -> String {
    format!(
        "{SETUP_HEADER}\n\
         https://:{SETUP_PORT} {{\n\
         \ttls internal {{\n\
         \t\ton_demand\n\
         \t}}\n\
         \treverse_proxy 127.0.0.1:{SETUP_UPSTREAM_PORT}\n\
         }}\n"
    )
}

/// Write the OOBE's site into `config_dir`. Returns whether it changed.
///
/// # Errors
/// Fails when the file cannot be written.
pub fn write_setup_site(config_dir: &Path) -> Result<bool> {
    let path = safe_join(config_dir, SETUP_SITE_FILE)?;
    crate::auth::store::replace_if_changed(&path, render_setup_site().as_bytes(), SITE_MODE)
}

/// Remove the OOBE's site. Returns whether it existed.
///
/// # Errors
/// Fails when the file exists but cannot be removed.
pub fn remove_setup_site(config_dir: &Path) -> Result<bool> {
    crate::auth::store::remove_if_exists(&safe_join(config_dir, SETUP_SITE_FILE)?)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn upstreams_need_one_host_and_an_unreserved_port() {
        for ok in ["127.0.0.1:8080", "[::1]:8080", "localhost:3000", "http://app.lan:80/"] {
            validate_upstream(ok).unwrap();
        }
        for bad in [
            "127.0.0.1:2019",
            "[::1]:2019",
            "localhost:2019",
            "http://127.0.0.1:2019/",
            "127.0.0.1:6624",
            "127.0.0.1",
            ":8080",
            "127.0.0.1:x",
            "127.0.0.1:1 unix//run/x.sock",
        ] {
            assert!(validate_upstream(bad).is_err(), "{bad}");
        }
    }

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
            upstream: "127.0.0.1:3972".into(),
            public_root: None,
        };
        assert_eq!(
            domain.render().unwrap(),
            format!(
                "{DASHBOARD_HEADER}\nserver.example.com {{\n\treverse_proxy 127.0.0.1:3972\n}}\n"
            )
        );
        let ip = DashboardSite {
            address: "https://[2001:db8::1]".into(),
            tls: DashboardTls::Internal,
            upstream: "127.0.0.1:3972".into(),
            public_root: None,
        };
        assert!(
            ip.render()
                .unwrap()
                .contains("https://[2001:db8::1] {\n\ttls internal\n")
        );
        let injected = DashboardSite {
            address: "evil.example.com {\n".into(),
            ..domain.clone()
        };
        injected.render().unwrap_err();
        let public = DashboardSite {
            public_root: Some("/var/lib/tetra-public".into()),
            ..domain.clone()
        };
        assert!(public.render().unwrap().contains(
            "\thandle_path /public/* {\n\t\troot * /var/lib/tetra-public\n\t\tfile_server\n\t}\n\treverse_proxy"
        ));
        let injected = DashboardSite {
            public_root: Some("/srv {\n".into()),
            ..domain
        };
        injected.render().unwrap_err();
    }

    #[test]
    fn renders_dns_01_dashboard_sites_with_placeholders_only() {
        let site = DashboardSite {
            address: "server.example.com".into(),
            tls: DashboardTls::Dns {
                provider: "powerdns",
                fields: vec![
                    ("server_url", DnsValue::Literal("https://ns.example.com".into())),
                    ("api_token", DnsValue::Env("TETRA_DNS_API_TOKEN".into())),
                ],
            },
            upstream: "127.0.0.1:3972".into(),
            public_root: None,
        };
        assert_eq!(
            site.render().unwrap(),
            format!(
                "{DASHBOARD_HEADER}\nserver.example.com {{\n\ttls {{\n\t\tdns powerdns {{\n\
                 \t\t\tserver_url \"https://ns.example.com\"\n\
                 \t\t\tapi_token {{env.TETRA_DNS_API_TOKEN}}\n\
                 \t\t}}\n\t}}\n\treverse_proxy 127.0.0.1:3972\n}}\n"
            )
        );
        for (key, value) in [
            ("api_token", DnsValue::Env("HOME}".into())),
            ("api_token", DnsValue::Env(String::new())),
            ("api_token", DnsValue::Literal("a\" }\n".into())),
            ("api_token", DnsValue::Literal("with space".into())),
            ("api_token", DnsValue::Literal("{env.HOME}".into())),
            ("api_token", DnsValue::Literal(String::new())),
            ("Key", DnsValue::Literal("x".into())),
        ] {
            let site = DashboardSite {
                tls: DashboardTls::Dns {
                    provider: "cloudflare",
                    fields: vec![(key, value)],
                },
                ..site.clone()
            };
            site.render().unwrap_err();
        }
    }

    #[test]
    fn setup_site_serves_the_oobe_with_the_internal_ca() {
        assert_eq!(
            render_setup_site(),
            format!(
                "{SETUP_HEADER}\nhttps://:6623 {{\n\ttls internal {{\n\t\ton_demand\n\t}}\n\
                 \treverse_proxy 127.0.0.1:6624\n}}\n"
            )
        );
        let dir = tempfile::tempdir().unwrap();
        assert!(write_setup_site(dir.path()).unwrap());
        assert!(!write_setup_site(dir.path()).unwrap());
        assert!(dir.path().join(SETUP_SITE_FILE).exists());
        // Not an app site.
        assert_eq!(list_sites(dir.path()).unwrap().len(), 0);
        assert!(remove_setup_site(dir.path()).unwrap());
        assert!(!remove_setup_site(dir.path()).unwrap());
    }

    #[test]
    fn sites_use_terra_caddys_drop_in_directory() {
        assert_eq!(DEFAULT_CONFIG_DIR, "/etc/caddy/Caddyfile.d");
        assert_eq!(
            site_filename("app.example.com").unwrap(),
            "app_example_com.caddyfile"
        );
        let dir = tempfile::tempdir().unwrap();
        // Files with other extensions (such as the `*.caddy` sites of
        // released versions, see `migrate_legacy_sites`) are not imported,
        // so not listed.
        fs::write(
            dir.path().join("old_example_com.caddy"),
            format!("{MANAGED_HEADER}\n# tetra: {{\"domain\":\"old.example.com\",\"upstream\":\"127.0.0.1:1\",\"tls\":true}}\n"),
        )
        .unwrap();
        assert_eq!(list_sites(dir.path()).unwrap().len(), 0);
    }

    #[test]
    fn sites_of_released_versions_are_moved_to_the_drop_in_directory() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("tetra-sites");
        let sites = dir.path().join("Caddyfile.d");
        let site = |domain: &str| {
            SiteMetadata::new(domain, "127.0.0.1:8080", true).unwrap().render().unwrap()
        };
        // Missing: nothing to do.
        assert_eq!(migrate_legacy_sites(&legacy, &sites).unwrap(), Vec::<PathBuf>::new());
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("app_example_com.caddy"), site("app.example.com")).unwrap();
        // The operator's own files stay, and so does a site whose new name
        // is taken.
        fs::write(legacy.join("mine.caddy"), "mine.example.com {\n}\n").unwrap();
        fs::write(legacy.join("taken_example_com.caddy"), site("taken.example.com")).unwrap();
        fs::create_dir_all(&sites).unwrap();
        fs::write(sites.join("taken_example_com.caddyfile"), "operator's\n").unwrap();

        let moved = migrate_legacy_sites(&legacy, &sites).unwrap();
        assert_eq!(moved, [sites.join("app_example_com.caddyfile")]);
        assert!(!legacy.join("app_example_com.caddy").exists());
        assert!(legacy.join("mine.caddy").exists());
        assert!(legacy.join("taken_example_com.caddy").exists());
        assert_eq!(fs::read_to_string(sites.join("taken_example_com.caddyfile")).unwrap(), "operator's\n");
        // `list` sees them in its directory, which is where `agent-serve`
        // migrates to: `DEFAULT_CONFIG_DIR` unless a request names another.
        let listed = ReverseProxyModule
            .handle("list", serde_json::json!({ "config_dir": sites }), None)
            .unwrap();
        assert_eq!(listed["sites"].as_array().unwrap().len(), 1);
        assert_eq!(listed["sites"][0]["domain"], "app.example.com");
        let default: List = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(default.config_dir, Path::new(DEFAULT_CONFIG_DIR));
        // Once moved, there is nothing left to do.
        assert_eq!(migrate_legacy_sites(&legacy, &sites).unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn dashboard_site_is_not_listed_as_an_app_site() {
        let dir = tempfile::tempdir().unwrap();
        let site = DashboardSite {
            address: "server.example.com".into(),
            tls: DashboardTls::Automatic,
            upstream: "127.0.0.1:3972".into(),
            public_root: None,
        };
        let written = write_dashboard_site(dir.path(), &site.render().unwrap()).unwrap();
        assert_eq!(written["changed"], true);
        let path = dir.path().join(DASHBOARD_SITE_FILE);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            SITE_MODE
        );
        let again = write_dashboard_site(dir.path(), &site.render().unwrap()).unwrap();
        assert_eq!(again["changed"], false);
        assert_eq!(list_sites(dir.path()).unwrap().len(), 0);
    }

    #[test]
    fn write_and_delete_leave_unmanaged_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        let write = |domain: &str| Write {
            config_dir: dir.path().to_path_buf(),
            domain: domain.into(),
            upstream: "127.0.0.1:9999".into(),
            tls: true,
            dry_run: false,
            reload: false,
        };
        let delete = |domain: &str| Delete {
            config_dir: dir.path().to_path_buf(),
            domain: domain.into(),
            dry_run: false,
            reload: false,
        };

        // Tetra's own sites' names are reserved, even before they exist.
        for reserved in ["00-ultramarine-dashboard", "00-ultramarine-setup"] {
            write(reserved).handle(None).unwrap_err();
            delete(reserved).handle(None).unwrap_err();
        }

        let operator = dir.path().join("mine_example_com.caddyfile");
        fs::write(&operator, "mine.example.com {\n}\n").unwrap();
        write("mine.example.com").handle(None).unwrap_err();
        delete("mine.example.com").handle(None).unwrap_err();
        assert_eq!(
            fs::read_to_string(&operator).unwrap(),
            "mine.example.com {\n}\n"
        );

        // Managed sites can still be rewritten and deleted.
        write("app.example.com").handle(None).unwrap();
        write("app.example.com").handle(None).unwrap();
        delete("app.example.com").handle(None).unwrap();
        assert!(!dir.path().join("app_example_com.caddyfile").exists());
    }

    #[test]
    fn dry_run_write_does_not_create_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("demo_example_com.caddyfile");
        let response = Write {
            config_dir: dir.path().to_path_buf(),
            domain: "demo.example.com".into(),
            upstream: "127.0.0.1:3972".into(),
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
