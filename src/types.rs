//! Shared domain types used by Tetra's agent modules

use serde_norway::Value as YamlValue;

use crate::agent::module_support::SelinuxOptions;
use crate::catalog::{AppRecipe, RenderedResource};
use crate::prelude::*;

fn read_text(path: &Path) -> Result<String> {
    use std::io::Read as _;
    let file = open_regular(path, fs::OpenOptions::new().read(true))?;
    let mut text = String::new();
    file.take(MAX_TEXT_LEN + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("failed to read `{}`", path.display()))?;
    ensure!(
        u64::try_from(text.len()).is_ok_and(|len| len <= MAX_TEXT_LEN),
        "`{}` is larger than {MAX_TEXT_LEN} bytes",
        path.display()
    );
    Ok(text)
}

/// Replace `path` with `contents` unless `dry_run`. Writes in place so the
/// file keeps its owner, mode and SELinux label.
fn write_text(path: &Path, contents: &str, dry_run: bool) -> Result<()> {
    use std::io::Write as _;
    if !dry_run {
        let mut file = open_regular(path, fs::OpenOptions::new().write(true).create(true))?;
        file.set_len(0)
            .and_then(|()| file.write_all(contents.as_bytes()))
            .with_context(|| format!("failed to write `{}`", path.display()))?;
    }
    Ok(())
}

/// Largest file [`read_text`] returns (a response must fit one WebSocket
/// message).
const MAX_TEXT_LEN: u64 = 16 << 20;

/// Open `path` only if it is a regular file. `O_NONBLOCK`, so a FIFO fails
/// instead of blocking the agent's one-at-a-time dispatch queue forever; a
/// device such as `/dev/zero` is refused before it fills memory.
fn open_regular(path: &Path, options: &mut fs::OpenOptions) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = options
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .with_context(|| format!("failed to open `{}`", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "`{}` is not a regular file",
        path.display()
    );
    Ok(file)
}

#[derive(Debug, Deserialize)]
pub struct FileReadRequest {
    pub path: PathBuf,
}

impl FileReadRequest {
    pub fn read(&self) -> Result<String> {
        read_text(&self.path)
    }
}

#[derive(Debug, Deserialize)]
pub struct FileWriteRequest {
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

impl FileWriteRequest {
    pub fn write(&self) -> Result<()> {
        write_text(&self.path, &self.contents, self.dry_run)
    }
}

#[derive(Debug, Deserialize)]
pub struct NetworkInterfaceRequest {
    pub interface: Option<String>,
}

impl NetworkInterfaceRequest {
    #[must_use]
    pub fn ip_args(&self) -> Vec<String> {
        let mut args = vec!["-json".into(), "addr".into(), "show".into()];
        if let Some(interface) = &self.interface {
            args.extend(["dev".into(), interface.clone()]);
        }
        args
    }
}

/// Payload for `network.get_config`. The path must name a `.nmconnection`
/// file directly inside `/etc/NetworkManager/system-connections/`.
#[derive(Debug, Deserialize)]
pub struct NetworkConfigRequest {
    pub path: PathBuf,
}

/// Payload for `network.set_config`. The path is restricted like
/// [`NetworkConfigRequest`]; the file is always written `0600` and relabeled
/// with its default SELinux context.
#[derive(Debug, Deserialize)]
pub struct NetworkWriteConfigRequest {
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

/// Payload for `network.configure`: a structured profile for one Ethernet
/// interface that Tetra validates and renders into a NetworkManager keyfile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfigureRequest {
    /// Kernel interface name, e.g. `enp1s0`.
    pub interface: String,
    /// Connection profile name and keyfile stem; defaults to `interface`.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ipv4: Ipv4Config,
    #[serde(default)]
    pub ipv6: Ipv6Config,
    /// Wired 802.1X authentication, written to the keyfile's `[802-1x]`
    /// section.
    #[serde(default)]
    pub wired_8021x: Option<Box<Wired8021x>>,
    #[serde(default)]
    pub dry_run: bool,
}

/// `wired_8021x` for [`NetworkConfigureRequest`], also used for
/// `wpa-enterprise` Wi-Fi. `Debug` leaves out the passwords.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wired8021x {
    pub eap: EapMethod,
    pub identity: String,
    /// Outer identity for tunneled methods (`peap`, `ttls`).
    #[serde(default)]
    pub anonymous_identity: Option<String>,
    /// Required for `peap`, `ttls`, `pwd` and `md5`.
    #[serde(default)]
    pub password: Option<String>,
    /// CA certificate that signed the authentication server's certificate.
    /// This and the client certificate and key are each an absolute path or
    /// PEM contents, which Tetra stores root-only and refers to by path.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Client certificate and key, required for `tls`.
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub private_key_password: Option<String>,
    /// Accept only an authentication server whose certificate names this
    /// domain or a subdomain of it (`802-1x.domain-suffix-match`).
    #[serde(default)]
    pub domain_suffix_match: Option<String>,
    /// Inner authentication for `peap` and `ttls` (default `mschapv2`).
    #[serde(default)]
    pub phase2: Option<Phase2Method>,
}

impl std::fmt::Debug for Wired8021x {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PEM contents are not shown, only paths.
        let shown = |value: &Option<String>| {
            value
                .as_deref()
                .map(|value| if is_pem(value) { "<pem>" } else { value }.to_owned())
        };
        // The private key could be in any encoding (a BOM before the PEM,
        // base64 DER, ...), so only a plain absolute path is shown.
        let private_key = self.private_key.as_deref().map(|value| {
            if Path::new(value).is_absolute() && !value.chars().any(char::is_control) {
                value
            } else {
                "<redacted>"
            }
        });
        f.debug_struct("Wired8021x")
            .field("eap", &self.eap)
            .field("identity", &self.identity)
            .field("ca_cert", &shown(&self.ca_cert))
            .field("client_cert", &shown(&self.client_cert))
            .field("private_key", &private_key)
            .field("domain_suffix_match", &self.domain_suffix_match)
            .field("phase2", &self.phase2)
            .finish_non_exhaustive()
    }
}

/// Whether an 802.1X certificate or key field holds PEM contents rather than
/// a path.
#[must_use]
pub fn is_pem(value: &str) -> bool {
    value.trim_start().starts_with("-----BEGIN ")
}

/// EAP method for [`Wired8021x`] (NetworkManager `802-1x.eap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EapMethod {
    Tls,
    Peap,
    Ttls,
    Pwd,
    Md5,
}

/// Inner method for [`Wired8021x`] (NetworkManager `802-1x.phase2-auth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase2Method {
    Mschapv2,
    Mschap,
    Pap,
    Chap,
    Gtc,
    Md5,
}

/// `ipv4.method` for [`NetworkConfigureRequest`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv4Method {
    /// DHCP.
    #[default]
    Auto,
    Manual,
    Disabled,
}

/// `ipv6.method` for [`NetworkConfigureRequest`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Method {
    /// `SLAAC`, with `DHCPv6` when router advertisements ask for it.
    #[default]
    Auto,
    /// `DHCPv6` only, without `SLAAC`.
    Dhcp,
    Manual,
    /// Only the link-local address; not routable.
    LinkLocal,
    Disabled,
}

/// One address of a manual configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpAddressConfig<A> {
    pub address: A,
    pub prefix_length: u8,
}

/// One address family's section of [`NetworkConfigureRequest`].
///
/// Using the family's address type means a value of the wrong family (an
/// IPv6 DNS server under `ipv4`, say) fails to deserialize.
#[derive(Debug, Clone, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "M: Deserialize<'de> + Default, A: Deserialize<'de>")
)]
pub struct IpConfig<M, A> {
    #[serde(default)]
    pub method: M,
    /// Required for, and only allowed with, `manual`.
    #[serde(default = "Vec::new")]
    pub addresses: Vec<IpAddressConfig<A>>,
    /// Only allowed with `manual`.
    #[serde(default = "Option::default")]
    pub gateway: Option<A>,
    /// Static DNS servers; not allowed when the family is disabled or
    /// link-local.
    #[serde(default = "Vec::new")]
    pub dns: Vec<A>,
}

impl<M: Default, A> Default for IpConfig<M, A> {
    fn default() -> Self {
        Self {
            method: M::default(),
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
        }
    }
}

pub type Ipv4Config = IpConfig<Ipv4Method, std::net::Ipv4Addr>;
pub type Ipv6Config = IpConfig<Ipv6Method, std::net::Ipv6Addr>;

/// Payload for `network.confirm`: keeps a change made by `network.configure`
/// that would otherwise be rolled back.
#[derive(Debug, Deserialize)]
pub struct NetworkConfirmRequest {
    pub token: String,
}

/// Payload for `network.scan_wifi`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScanWifiRequest {
    /// Wireless interface to scan with, e.g. `wlan0`.
    pub interface: String,
    /// `true` always rescans, `false` never does; by default NetworkManager
    /// rescans when its last scan is older than 30 seconds.
    #[serde(default)]
    pub rescan: Option<bool>,
}

/// Payload for `network.connect_wifi`: a Wi-Fi profile for one interface
/// that Tetra renders into a NetworkManager keyfile and activates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConnectWifiRequest {
    /// Wireless interface, e.g. `wlan0`.
    pub interface: String,
    pub ssid: String,
    /// Probe for a network that does not broadcast its SSID. Networks the
    /// last scan did not see are treated as hidden anyway.
    #[serde(default)]
    pub hidden: bool,
    pub security: WifiSecurity,
    #[serde(default)]
    pub dry_run: bool,
}

/// `security` for [`NetworkConnectWifiRequest`], tagged by `type`.
/// `Debug` leaves out the passwords.
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WifiSecurity {
    /// A struct variant so that stray fields are refused.
    #[allow(clippy::empty_enum_variants_with_brackets)]
    Open {},
    /// WPA2 or WPA3 with a passphrase.
    WpaPersonal { password: String },
    /// WPA2 or WPA3 Enterprise (802.1X), with the same settings as
    /// [`Wired8021x`].
    WpaEnterprise(Box<Wired8021x>),
}

impl std::fmt::Debug for WifiSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open {} => f.write_str("Open"),
            Self::WpaPersonal { .. } => f.debug_struct("WpaPersonal").finish_non_exhaustive(),
            Self::WpaEnterprise(settings) => {
                f.debug_tuple("WpaEnterprise").field(settings).finish()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DryRunRequest {
    #[serde(default)]
    pub dry_run: bool,
}

/// Default `nfs` config path; non-admins may not override it.
pub const EXPORTS_PATH: &str = "/etc/exports";
/// Default `samba` config path; non-admins may not override it.
pub const SAMBA_CONFIG_PATH: &str = "/etc/samba/smb.conf";

fn default_exports_path() -> PathBuf {
    PathBuf::from(EXPORTS_PATH)
}

#[derive(Debug, Deserialize)]
pub struct NfsConfigRequest {
    #[serde(default = "default_exports_path")]
    pub path: PathBuf,
}

impl NfsConfigRequest {
    pub fn read(&self) -> Result<String> {
        read_text(&self.path)
    }
}

#[derive(Debug, Deserialize)]
pub struct NfsWriteConfigRequest {
    #[serde(default = "default_exports_path")]
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

impl NfsWriteConfigRequest {
    pub fn write(&self) -> Result<()> {
        write_text(&self.path, &self.contents, self.dry_run)
    }
}

fn default_samba_config_path() -> PathBuf {
    PathBuf::from(SAMBA_CONFIG_PATH)
}

#[derive(Debug, Deserialize)]
pub struct SambaConfigRequest {
    #[serde(default = "default_samba_config_path")]
    pub path: PathBuf,
}

impl SambaConfigRequest {
    pub fn read(&self) -> Result<String> {
        read_text(&self.path)
    }
}

#[derive(Debug, Deserialize)]
pub struct SambaWriteConfigRequest {
    #[serde(default = "default_samba_config_path")]
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

impl SambaWriteConfigRequest {
    pub fn write(&self) -> Result<()> {
        write_text(&self.path, &self.contents, self.dry_run)
    }
}

/// Which service manager a `services` action talks to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceScope {
    /// The system manager.
    #[default]
    System,
    /// The user manager of whoever the command runs as (`systemctl --user`).
    User,
    /// The user manager of the `ultramarine-apps` account that user apps run
    /// under (`systemctl --user -M ultramarine-apps@`).
    Apps,
}

impl ServiceScope {
    /// `args` for `systemctl` in this scope, run as root (or as anyone, for
    /// `system` and `user`).
    #[must_use]
    pub fn command_args<const N: usize>(self, args: [&str; N]) -> Vec<&str> {
        self.command_args_as(args, false)
    }

    /// `args` for `systemctl` in this scope. In `apps` scope, a command run
    /// as the apps account itself (`as_apps`) reaches its manager with
    /// `--user`; root needs `-M ultramarine-apps@`.
    #[must_use]
    pub fn command_args_as<const N: usize>(self, args: [&str; N], as_apps: bool) -> Vec<&str> {
        let prefix: &[&str] = match self {
            Self::System => &[],
            Self::User => &["--user"],
            Self::Apps if as_apps => &["--user"],
            Self::Apps => &[
                "--user",
                "-M",
                crate::agent::apps_account::SYSTEMCTL_MACHINE,
            ],
        };
        let mut scoped = Vec::with_capacity(args.len().saturating_add(prefix.len()));
        scoped.extend_from_slice(prefix);
        scoped.extend(args);
        scoped
    }
}

/// Where an app, or a Quadlet of the `quadlets` module, is installed.
///
/// There is no per-user scope: every user app is a rootless Quadlet of the
/// one `ultramarine-apps` account, whoever installed it. A payload or stored
/// manifest that still says `user` is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppScope {
    /// Rootless, under the `ultramarine-apps` account: units in its
    /// `~/.config/containers/systemd`, companion files and manifests in its
    /// `~/.local/share/tetra/quadlets`, services in its user manager.
    #[default]
    Apps,
    /// Rootful, for real system services: `/etc/containers/systemd`,
    /// `/var/lib/tetra/quadlets` and the system manager.
    System,
}

impl From<AppScope> for ServiceScope {
    fn from(scope: AppScope) -> Self {
        match scope {
            AppScope::Apps => Self::Apps,
            AppScope::System => Self::System,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ServiceRequest {
    pub service: String,
    #[serde(default)]
    pub scope: ServiceScope,
    #[serde(default)]
    pub dry_run: bool,
}

/// Payload for `services.list`; all fields are optional so `{}` lists system
/// services as before.
#[derive(Debug, Deserialize)]
pub struct ServiceListRequest {
    #[serde(default)]
    pub scope: ServiceScope,
}

/// `true`, for `#[serde(default = "crate::types::default_true")]`.
pub(crate) const fn default_true() -> bool {
    true
}

/// Target of an `apps.remove` action.
///
/// Identifies which installed app to remove, in which scope, and whether to
/// converge systemd (stop/disable + daemon-reload) while removing it. The
/// directory overrides exist so tests and custom deployments can redirect the
/// Quadlet scan dir and the companion data root.
#[derive(Debug, Deserialize)]
pub struct AppRequest {
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub converge: bool,
    #[serde(default)]
    pub dry_run: bool,
}

/// Where an app's recipe comes from.
///
/// A recipe is either shipped inline (`recipe` + `templates`) or referenced
/// on disk (`recipe_path` + `templates_dir`); exactly one form must be given.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AppRecipeSource {
    Inline {
        recipe: String,
        #[serde(default)]
        templates: BTreeMap<String, String>,
    },
    File {
        recipe_path: PathBuf,
        templates_dir: PathBuf,
    },
}

impl AppRecipeSource {
    /// Parse the recipe.
    pub fn load(&self) -> Result<AppRecipe> {
        match self {
            Self::Inline { recipe, .. } => AppRecipe::load_str(recipe),
            Self::File { recipe_path, .. } => AppRecipe::load(recipe_path),
        }
    }

    /// Render the recipe with `values`, returning the parsed recipe alongside
    /// the rendered resources so callers can record `recipe_id`/`version`.
    /// Generated values are added to `values` first, so callers store them.
    pub fn render(
        &self,
        values: &mut BTreeMap<String, YamlValue>,
    ) -> Result<(AppRecipe, Vec<RenderedResource>)> {
        let recipe = self.load()?;
        recipe.fill_generated(values);
        let resources = match self {
            Self::Inline { templates, .. } => recipe.render_with_templates(values, templates)?,
            Self::File { templates_dir, .. } => recipe.render(values, templates_dir)?,
        };
        Ok((recipe, resources))
    }
}

/// Payload for `apps.create`: cook a recipe into an installed app bundle.
///
/// `values` are merged over `values_path` (inline wins), so a dashboard can
/// ship a defaults file plus per-instance overrides. `converge` controls the
/// systemd phase; when `false` only files are written and systemd is left
/// untouched (no daemon-reload, no enable/start), letting a controller run
/// that phase itself through the `services` module.
#[derive(Debug, Deserialize)]
pub struct AppCreateRequest {
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
    pub recipe: Option<String>,
    #[serde(default)]
    pub templates: BTreeMap<String, String>,
    pub recipe_path: Option<PathBuf>,
    pub templates_dir: Option<PathBuf>,
    pub values_path: Option<PathBuf>,
    #[serde(default)]
    pub values: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
    #[serde(default = "default_true")]
    pub converge: bool,
    #[serde(default)]
    pub dry_run: bool,
}

impl AppCreateRequest {
    /// Build the recipe source for a `create`: exactly one of the inline
    /// bundle or the on-disk paths must be given.
    pub fn recipe_source(&self) -> Result<AppRecipeSource> {
        match (&self.recipe, &self.recipe_path) {
            (Some(recipe), None) => Ok(AppRecipeSource::Inline {
                recipe: recipe.clone(),
                templates: self.templates.clone(),
            }),
            (None, Some(recipe_path)) => Ok(AppRecipeSource::File {
                recipe_path: recipe_path.clone(),
                templates_dir: self
                    .templates_dir
                    .clone()
                    .context("`templates_dir` is required with `recipe_path`")?,
            }),
            (Some(_), Some(_)) => bail!("pass either `recipe` or `recipe_path`, not both"),
            (None, None) => {
                bail!("`create` requires either `recipe` (inline) or `recipe_path` (file)")
            }
        }
    }
}

/// Payload for `apps.update`: re-cook an installed app.
///
/// `values` are merged per-key over the stored values from `create` (or the
/// last `update`), so secrets do not have to be re-sent on every edit.
/// Passing a new `recipe` / `recipe_path` swaps the recipe source (e.g. a
/// recipe upgrade).
#[derive(Debug, Deserialize)]
pub struct AppUpdateRequest {
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
    pub recipe: Option<String>,
    pub templates: Option<BTreeMap<String, String>>,
    pub recipe_path: Option<PathBuf>,
    pub templates_dir: Option<PathBuf>,
    #[serde(default)]
    pub values: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
    #[serde(default = "default_true")]
    pub converge: bool,
    #[serde(default)]
    pub dry_run: bool,
}

impl AppUpdateRequest {
    /// Build the replacement recipe source for an `update`, or `None` to keep
    /// the stored one. An inline recipe with no `templates` replaces the
    /// template bundle with an empty one; callers keeping the same templates
    /// can omit the field only when the stored source is reused unchanged.
    pub fn recipe_source(&self) -> Result<Option<AppRecipeSource>> {
        match (&self.recipe, &self.recipe_path) {
            (Some(recipe), None) => Ok(Some(AppRecipeSource::Inline {
                recipe: recipe.clone(),
                templates: self.templates.clone().unwrap_or_default(),
            })),
            (None, Some(recipe_path)) => Ok(Some(AppRecipeSource::File {
                recipe_path: recipe_path.clone(),
                templates_dir: self
                    .templates_dir
                    .clone()
                    .context("`templates_dir` is required with `recipe_path`")?,
            })),
            (Some(_), Some(_)) => bail!("pass either `recipe` or `recipe_path`, not both"),
            (None, None) => Ok(None),
        }
    }
}

/// Payload for `apps.get`: read one installed app's manifest and on-disk
/// state. Read-only, so there is no `dry_run`.
#[derive(Debug, Deserialize)]
pub struct AppGetRequest {
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
}

/// Payload for `apps.list`: enumerate installed app bundles under the
/// companion data root. Read-only.
#[derive(Debug, Deserialize)]
pub struct AppListRequest {
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
}

/// The on-disk record of one installed app.
///
/// Serialized as `<bundle>/app.json` under the companion data root
/// (`~ultramarine-apps/.local/share/tetra/quadlets/<name>/app.json` in apps
/// scope, `/var/lib/tetra/quadlets/<name>/app.json` in system scope), tying
/// the app to the recipe and values it was cooked from.
///
/// The manifest is what makes the bundle self-contained: `update` re-renders
/// from the stored recipe source and merged values, `remove` derives the
/// units/services to tear down, and config backups can snapshot one directory
/// per app. `values` may contain secrets, so the manifest is private (`0600`,
/// root's or the apps account's) and is excluded from secret-free backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    /// Manifest schema version; currently 1.
    pub version: u32,
    pub name: String,
    pub scope: AppScope,
    pub recipe_id: String,
    pub recipe_version: String,
    pub recipe: AppRecipeSource,
    #[serde(default)]
    pub values: BTreeMap<String, YamlValue>,
    /// Keys that were `Secret` parameters at any render. Redaction uses this
    /// snapshot, so editing a recipe file cannot declassify a stored value.
    #[serde(default)]
    pub secret_keys: std::collections::BTreeSet<String>,
    /// Quadlet unit filenames installed into the scan directory.
    #[serde(default)]
    pub units: Vec<String>,
    /// Companion file paths, relative to the bundle directory.
    #[serde(default)]
    pub files: Vec<String>,
    /// Seconds since the Unix epoch.
    pub created_at: u64,
    pub updated_at: u64,
}

impl AppManifest {
    /// The systemd services Quadlet generates for the app's units.
    /// `.network`/`.volume` units have no service of their own — Podman pulls
    /// them in as dependencies of the containers that use them.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        self.units
            .iter()
            .filter_map(|unit| unit_service_name(unit))
            .collect()
    }
}

/// Derive the systemd service Quadlet generates for a unit filename, or
/// `None` for units that are not directly started (`.network`, `.volume`).
/// `.container`/`.kube` produce `<stem>.service`; `.pod` produces
/// `<stem>-pod.service`.
fn unit_service_name(filename: &str) -> Option<String> {
    let (stem, extension) = filename.rsplit_once('.')?;
    match extension {
        "container" | "kube" => Some(format!("{stem}.service")),
        "pod" => Some(format!("{stem}-pod.service")),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct ServiceLogsRequest {
    pub service: String,
    #[serde(default)]
    pub scope: ServiceScope,
    #[serde(default = "default_log_lines")]
    pub lines: u16,
}

#[derive(Debug, Deserialize)]
pub struct DaemonReloadRequest {
    #[serde(default)]
    pub scope: ServiceScope,
    #[serde(default)]
    pub dry_run: bool,
}

const fn default_log_lines() -> u16 {
    100
}

#[derive(Debug, serde::Serialize)]
pub struct ServiceStatus {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

impl ServiceStatus {
    #[must_use]
    pub fn parse_all(stdout: &str) -> Vec<Self> {
        stdout.lines().filter_map(Self::parse).collect()
    }

    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let unit = fields.next()?;
        let load = fields.next()?;
        let active = fields.next()?;
        let sub = fields.next()?;
        Some(Self {
            unit: unit.to_owned(),
            load: load.to_owned(),
            active: active.to_owned(),
            sub: sub.to_owned(),
            description: fields.collect::<Vec<_>>().join(" "),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct VirtualMachineCreateRequest {
    pub xml_path: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
pub struct VirtualMachineLogsRequest {
    #[serde(default = "default_log_lines")]
    pub lines: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn file_write_request_honors_dry_run_and_writes_when_requested() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("managed.conf");
        let dry_run = FileWriteRequest {
            path: path.clone(),
            contents: "dry run".into(),
            dry_run: true,
            selinux: None,
        };
        dry_run.write().unwrap();
        assert!(!path.exists());

        let write = FileWriteRequest {
            path: path.clone(),
            contents: "written".into(),
            dry_run: false,
            selinux: None,
        };
        write.write().unwrap();
        assert_eq!(FileReadRequest { path }.read().unwrap(), "written");
    }

    #[test]
    fn wired_8021x_debug_shows_only_a_private_key_path() {
        let debug = |private_key: &str| {
            let settings: Wired8021x = serde_json::from_value(json!({
                "eap": "tls",
                "identity": "host",
                "private_key": private_key,
            }))
            .unwrap();
            format!("{settings:?}")
        };
        assert!(debug("/etc/pki/tls/private/host.key").contains("/etc/pki/tls/private/host.key"));
        for secret in [
            "-----BEGIN PRIVATE KEY-----\nS3CRET\n-----END PRIVATE KEY-----\n",
            "\u{feff}-----BEGIN PRIVATE KEY-----\nS3CRET\n-----END PRIVATE KEY-----\n",
            "MIIEvS3CRETbase64DER",
            "/S3CRET\nline",
        ] {
            let shown = debug(secret);
            assert!(!shown.contains("S3CRET"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
    }

    #[test]
    fn network_interface_request_builds_optional_device_arguments() {
        assert_eq!(
            NetworkInterfaceRequest { interface: None }.ip_args(),
            ["-json", "addr", "show"]
        );
        assert_eq!(
            NetworkInterfaceRequest {
                interface: Some("eno1".into())
            }
            .ip_args(),
            ["-json", "addr", "show", "dev", "eno1"]
        );
    }

    #[test]
    fn configuration_requests_keep_their_module_defaults() {
        let nfs: NfsConfigRequest = serde_json::from_value(json!({})).unwrap();
        let samba: SambaConfigRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(nfs.path, PathBuf::from("/etc/exports"));
        assert_eq!(samba.path, PathBuf::from("/etc/samba/smb.conf"));
    }

    #[test]
    fn service_requests_default_and_apply_scope_consistently() {
        let logs: ServiceLogsRequest =
            serde_json::from_value(json!({ "service": "sshd" })).unwrap();
        assert_eq!(logs.lines, 100);
        assert_eq!(
            logs.scope.command_args(["status", "sshd"]),
            ["status", "sshd"]
        );
        assert_eq!(
            ServiceScope::User.command_args(["status", "sshd"]),
            ["--user", "status", "sshd"]
        );
        assert_eq!(
            ServiceScope::Apps.command_args(["start", "app.service"]),
            ["--user", "-M", "ultramarine-apps@", "start", "app.service"]
        );
        assert_eq!(
            ServiceScope::Apps.command_args_as(["status", "app.service"], true),
            ["--user", "status", "app.service"]
        );
    }

    #[test]
    fn apps_default_to_the_apps_account_and_user_scope_is_gone() {
        let list: AppListRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(list.scope, AppScope::Apps);
        let system: AppListRequest = serde_json::from_value(json!({ "scope": "system" })).unwrap();
        assert_eq!(system.scope, AppScope::System);
        let error = serde_json::from_value::<AppListRequest>(json!({ "scope": "user" }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown variant `user`"), "{error}");
        assert_eq!(ServiceScope::from(AppScope::Apps), ServiceScope::Apps);
        assert_eq!(ServiceScope::from(AppScope::System), ServiceScope::System);
    }

    #[test]
    fn service_status_parser_skips_malformed_rows_and_preserves_description() {
        let statuses = ServiceStatus::parse_all(
            "invalid\nsshd.service loaded active running OpenSSH server daemon\n",
        );
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].unit, "sshd.service");
        assert_eq!(statuses[0].description, "OpenSSH server daemon");
    }

    #[test]
    fn virtual_machine_log_request_defaults_to_one_hundred_lines() {
        let logs: VirtualMachineLogsRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(logs.lines, 100);
    }

    #[test]
    fn manifest_derives_service_names_from_unit_filenames() {
        let manifest = AppManifest {
            version: 1,
            name: "demo".into(),
            scope: AppScope::System,
            recipe_id: "demo-web".into(),
            recipe_version: "0.1.0".into(),
            recipe: AppRecipeSource::Inline {
                recipe: String::new(),
                templates: BTreeMap::new(),
            },
            values: BTreeMap::new(),
            secret_keys: std::collections::BTreeSet::new(),
            units: [
                "demo-web.container",
                "site.kube",
                "pair.pod",
                "demo-net.network",
                "demo-data.volume",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            files: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };

        assert_eq!(
            manifest.services(),
            ["demo-web.service", "site.service", "pair-pod.service"]
        );
    }
}
