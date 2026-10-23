//! Remote access to the dashboard: Tailscale and Cloudflare Tunnel.
//!
//! Both ship disabled (`tailscaled.service`, `cloudflared.service`). These
//! actions turn them on and off. Credentials reach the services without ever
//! appearing on a command line, in a unit file or in a log:
//!
//! - `tailscale_up` writes the auth key to a new root-only file under
//!   `/run/tetra` just long enough for `tailscale up --auth-key=file:<path>`,
//!   and keeps no copy (tailscaled keeps its own node key). If setting up
//!   fails, it undoes what it set up. By default it then shares Caddy's
//!   HTTPS port on the tailnet with `tailscale serve`; with `funnel: true`
//!   (never by default) it publishes it on the internet with
//!   `tailscale funnel` instead. Both forward raw TCP to Caddy, so the
//!   dashboard, apps, the public page and forward-auth behave as on the LAN
//!   once `access.set` uses this node's `*.ts.net` name as the hostname.
//!   Caddy gets that name's certificate from tailscaled, which a
//!   `tailscaled.service` drop-in allows for the `caddy` user
//!   (`TS_PERMIT_CERT_UID`). Without the PROXY protocol, which Caddy is not
//!   set up for, every forwarded client reaches Caddy from `127.0.0.1`.
//! - `cloudflared_set_token` seals the tunnel token in Tetra's secret store
//!   ([`crate::auth::secrets`]) as an encrypted systemd
//!   credential and installs a `cloudflared.service` drop-in that loads it
//!   (`LoadCredentialEncrypted=`) and points `TUNNEL_TOKEN_FILE` at it, so
//!   only the running service sees the plain token.
//!
//! `tailscale_disable` and `cloudflared_disable` stop and disable the service
//! and forget its drop-in (and cloudflared's token), even when the service is
//! missing.

use std::{
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
};

use crate::prelude::*;

use crate::agent::module_support::{
    Commands, NoPayload, drop_in, install_drop_in, parse_action, unit_enabled,
};
use crate::auth::{
    access::{AccessConfig, HTTPS_PORT},
    seal::{Sealer, SystemdCreds},
    secrets::{CLOUDFLARED_TOKEN, SecretStore},
    service::{AuthConfig, DEFAULT_STATE_DIR},
    store,
};

/// The remote access module, with the system's [`Paths`]. See
/// [`RemoteAccessModule::with_paths`] for others.
#[derive(Clone, Copy, Debug)]
pub struct RemoteAccessModule;

/// [`RemoteAccessModule`] with its files at other [`Paths`], such as the
/// ones an [`AuthConfig`](crate::auth::AuthConfig) configures.
#[derive(Clone, Debug)]
pub struct RemoteAccessWithPaths(Paths);

impl RemoteAccessModule {
    /// The module with its files at `paths`.
    #[must_use]
    pub const fn with_paths(paths: Paths) -> RemoteAccessWithPaths {
        RemoteAccessWithPaths(paths)
    }
}

const INFO: ModuleInfo = ModuleInfo {
    name: "remote_access",
    feature: "remote-access",
    description: "Reach the dashboard through Tailscale or a Cloudflare Tunnel.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "status",
        "tailscale_up",
        "tailscale_disable",
        "cloudflared_set_token",
        "cloudflared_disable",
    ],
    privileged_actions: &[
        "status",
        "tailscale_up",
        "tailscale_disable",
        "cloudflared_set_token",
        "cloudflared_disable",
    ],
};

pub const TAILSCALED: &str = "tailscaled.service";
pub const CLOUDFLARED: &str = "cloudflared.service";
/// Prefix of the per-call auth key file in [`Paths::run_dir`].
const TAILSCALE_KEY_FILE: &str = "tailscale-auth-key";
/// How long `tailscale up`, `serve` and `funnel` may wait (for the node to
/// come up, or for Serve or Funnel to be enabled in the tailnet) before
/// failing. Without a limit they wait forever, and the agent runs one
/// command at a time.
const TAILSCALE_TIMEOUT: &str = "60s";
/// The only ports Tailscale Funnel publishes.
const FUNNEL_PORTS: [u16; 3] = [443, 8443, 10_000];
/// The `tailscaled.service` drop-in that lets Caddy fetch the node's
/// `*.ts.net` certificate.
const TAILSCALED_DROP_IN: &str = "# Managed by Tetra (remote_access.tailscale_up).\n\
     [Service]\n\
     Environment=TS_PERMIT_CERT_UID=caddy\n";
const MAX_CREDENTIAL_LEN: usize = 4096;

/// Where this module keeps its files.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Sealed credentials (`/var/lib/tetra/secrets`).
    pub secrets: PathBuf,
    /// Root-only scratch space (`/run/tetra`).
    pub run_dir: PathBuf,
    /// Unit drop-ins (`/etc/systemd/system`).
    pub systemd_dir: PathBuf,
    /// The access configuration, for the dashboard's address.
    pub access: PathBuf,
}

impl Default for Paths {
    /// The paths of [`AuthConfig::system`] in its default state directory.
    fn default() -> Self {
        Self::for_config(&AuthConfig::system(DEFAULT_STATE_DIR.into()))
    }
}

impl Paths {
    /// The paths under `config`'s state, run and systemd directories.
    #[must_use]
    pub fn for_config(config: &AuthConfig) -> Self {
        Self {
            secrets: config.secrets_dir(),
            run_dir: config.run_dir.clone(),
            systemd_dir: config.systemd_dir.clone(),
            access: config.access_path(),
        }
    }

    fn secret_store(&self) -> SecretStore {
        SecretStore::new(self.secrets.clone())
    }

    /// Tetra's drop-in for `unit`.
    fn drop_in(&self, unit: &str) -> PathBuf {
        drop_in(&self.systemd_dir, unit)
    }
}

/// Whether Tailscale is set up: `tailscale_up` installed its
/// `tailscaled.service` drop-in in `systemd_dir`.
///
/// Until `tailscale_disable` removes it, Tailscale forwards the dashboard's
/// port as it was when `tailscale_up` ran, so `access.set` refuses to change
/// the port.
#[must_use]
pub fn tailscale_set_up(systemd_dir: &Path) -> bool {
    drop_in(systemd_dir, TAILSCALED).exists()
}

impl Mod for RemoteAccessModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, _user: Option<&str>) -> Result<Value> {
        handle(&Paths::default(), action, payload)
    }
}

impl Mod for RemoteAccessWithPaths {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, _user: Option<&str>) -> Result<Value> {
        handle(&self.0, action, payload)
    }
}

fn handle(paths: &Paths, action: &str, payload: Value) -> Result<Value> {
    if let Some(response) = INFO.metadata_response(action, &payload) {
        return Ok(response);
    }
    let action: Action = parse_action(action, payload)?;
    match action {
        Action::Status(NoPayload {}) => Ok(status()),
        Action::TailscaleUp(p) => tailscale_up(paths, &p.auth_key, p.serve, p.funnel, p.dry_run),
        Action::TailscaleDisable(p) => tailscale_disable(paths, p.dry_run),
        Action::CloudflaredSetToken(p) => {
            cloudflared_set_token(paths, &SystemdCreds, &p.token, p.dry_run)
        }
        Action::CloudflaredDisable(p) => cloudflared_disable(paths, p.dry_run),
    }
}

/// A credential in a payload. Its `Debug` output is redacted so it cannot
/// end up in a log through a `{:?}`.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Credential(String);

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(..)")
    }
}

/// An action and its payload. Not declared with `actions!`, whose handlers
/// cannot see the module's [`Paths`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Status(NoPayload),
    TailscaleUp(TailscaleUp),
    TailscaleDisable(Disable),
    CloudflaredSetToken(CloudflaredSetToken),
    CloudflaredDisable(Disable),
}

#[derive(Debug, Deserialize)]
struct TailscaleUp {
    auth_key: Credential,
    /// Share Caddy on the tailnet (`tailscale serve`).
    #[serde(default = "crate::types::default_true")]
    serve: bool,
    /// Publish Caddy on the internet (`tailscale funnel`). Only when
    /// explicitly set.
    #[serde(default)]
    funnel: bool,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct CloudflaredSetToken {
    token: Credential,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct Disable {
    #[serde(default)]
    dry_run: bool,
}

fn validate_credential(what: &str, value: &Credential) -> Result<()> {
    let value = &value.0;
    ensure!(
        (1..=MAX_CREDENTIAL_LEN).contains(&value.len())
            && value.chars().all(|c| c.is_ascii_graphic()),
        "the {what} must be 1 to {MAX_CREDENTIAL_LEN} printable ASCII characters without spaces"
    );
    Ok(())
}

/// The port Caddy serves the dashboard on, which Tailscale forwards as is
/// so the dashboard's origin is the same on the tailnet. It is read once,
/// which is why `access.set` refuses to change the port while Tailscale is
/// set up (see [`tailscale_set_up`]).
fn caddy_port(access: &Path) -> Result<u16> {
    Ok(AccessConfig::load(access)
        .context("failed to read the dashboard's port")?
        .and_then(|access| access.port)
        .unwrap_or(HTTPS_PORT))
}

fn tailscale_up(
    paths: &Paths,
    auth_key: &Credential,
    serve: bool,
    funnel: bool,
    dry_run: bool,
) -> Result<Value> {
    validate_credential("auth key", auth_key)?;
    let port = caddy_port(&paths.access)?;
    ensure!(
        !funnel || FUNNEL_PORTS.contains(&port),
        "Tailscale Funnel only publishes ports 443, 8443 and 10000, and the dashboard is on {port}"
    );
    // What was there before, so a failure only undoes what this call did.
    let was_running = !dry_run && (unit_enabled(TAILSCALED) || unit_active(TAILSCALED));
    let had_drop_in = paths.drop_in(TAILSCALED).exists();
    let new_drop_in = install_drop_in(&paths.drop_in(TAILSCALED), TAILSCALED_DROP_IN, dry_run)?;
    let mut commands = Commands::new(dry_run);
    let result =
        bring_up_tailscale(paths, &mut commands, auth_key, new_drop_in, serve, funnel, port);
    if let Err(error) = result {
        if dry_run {
            return Err(error);
        }
        let mut undo = Commands::new(false);
        return Err(match undo_tailscale_up(paths, was_running, had_drop_in, &mut undo) {
            Ok(()) => error,
            Err(undo) => anyhow::anyhow!(
                "{error:#}; undoing the Tailscale setup also failed: {undo:#}"
            ),
        });
    }
    // The name the OOBE should give `access.set`.
    let hostname = if dry_run { None } else { current_tailnet_hostname() };
    Ok(jsonf! {
        "enabled": true,
        "serve": serve || funnel,
        funnel,
        "target": forward_target(port),
        hostname,
        dry_run,
        "commands": commands.done,
    })
}

/// Where Tailscale forwards `port`: Caddy on the same port.
fn forward_target(port: u16) -> String {
    format!("tcp://127.0.0.1:{port}")
}

/// Start tailscaled, log in and forward Caddy's `port`.
fn bring_up_tailscale(
    paths: &Paths,
    commands: &mut Commands<'_>,
    auth_key: &Credential,
    new_drop_in: bool,
    serve: bool,
    funnel: bool,
    port: u16,
) -> Result<()> {
    if new_drop_in {
        // A running tailscaled only picks up the new environment on restart.
        commands.run("systemctl", &["daemon-reload"])?;
        commands.run("systemctl", &["enable", TAILSCALED])?;
        commands.run("systemctl", &["restart", TAILSCALED])?;
    } else {
        commands.run("systemctl", &["enable", "--now", TAILSCALED])?;
    }

    // A file of this call's own, so concurrent calls cannot read or delete
    // each other's key.
    let key_file = paths.run_dir.join(format!(
        "{TAILSCALE_KEY_FILE}-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let key_arg = format!("--auth-key=file:{}", key_file.display());
    if !commands.dry_run() {
        fs::create_dir_all(&paths.run_dir)
            .with_context(|| format!("failed to create `{}`", paths.run_dir.display()))?;
        write_key_file(&key_file, auth_key)?;
    }
    let timeout_arg = format!("--timeout={TAILSCALE_TIMEOUT}");
    let up = commands.run("tailscale", &["up", &timeout_arg, &key_arg]);
    if !commands.dry_run() {
        store::remove(&key_file)?;
    }
    up?;

    // Start from a clean serve configuration so turning serve or funnel off
    // takes effect.
    commands.run("tailscale", &["serve", "reset"])?;
    // Raw TCP, so Caddy terminates TLS and routes by name as on the LAN.
    let tcp = format!("--tcp={port}");
    let target = forward_target(port);
    // They have no timeout option, and wait (forever) for Serve or Funnel to
    // be enabled in the tailnet's policy.
    if funnel || serve {
        let forward = if funnel { "funnel" } else { "serve" };
        commands.run(
            "timeout",
            &[TAILSCALE_TIMEOUT, "tailscale", forward, "--bg", &tcp, &target],
        )?;
    }
    Ok(())
}

/// Create `path` (which must not exist) readable by root only, holding the
/// key. It is removed again if writing fails.
fn write_key_file(path: &Path, key: &Credential) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create `{}`", path.display()))?;
    if let Err(error) = file.write_all(key.0.as_bytes()) {
        drop(file);
        store::remove(path)?;
        return Err(error).with_context(|| format!("failed to write `{}`", path.display()));
    }
    Ok(())
}

/// Undo a failed `tailscale_up`: stop and disable tailscaled unless it was
/// enabled or running before, and remove the drop-in unless it was there
/// before. The node may stay logged in when only `tailscale serve` failed.
fn undo_tailscale_up(
    paths: &Paths,
    was_running: bool,
    had_drop_in: bool,
    commands: &mut Commands<'_>,
) -> Result<()> {
    let disabled = if was_running {
        Ok(())
    } else {
        commands.run("systemctl", &["disable", "--now", TAILSCALED])
    };
    let removed = if had_drop_in {
        Ok(())
    } else {
        store::remove(&paths.drop_in(TAILSCALED))
            .and_then(|()| commands.run("systemctl", &["daemon-reload"]))
    };
    disabled.and(removed)
}

fn tailscale_disable(paths: &Paths, dry_run: bool) -> Result<Value> {
    let mut commands = Commands::new(dry_run);
    // Fails when tailscaled is not running; nothing to reset then.
    commands.run_ignoring_failure("tailscale", &["serve", "reset"]);
    // Fails when tailscaled is not installed; clean up anyway.
    let disabled =
        commands.run_ignoring_failure("systemctl", &["disable", "--now", TAILSCALED]);
    let drop_in = paths.drop_in(TAILSCALED);
    let removed = if dry_run {
        drop_in.exists()
    } else {
        store::remove_if_exists(&drop_in)?
    };
    if removed {
        commands.run("systemctl", &["daemon-reload"])?;
    }
    let enabled = !disabled && unit_enabled(TAILSCALED);
    Ok(jsonf! { enabled, dry_run, "commands": commands.done })
}

/// The `cloudflared.service` drop-in that hands it the sealed token.
fn cloudflared_drop_in(credential: &Path) -> String {
    format!(
        "# Managed by Tetra (remote_access.cloudflared_set_token).\n\
         [Service]\n\
         LoadCredentialEncrypted={CLOUDFLARED_TOKEN}:{}\n\
         Environment=TUNNEL_TOKEN_FILE=%d/{CLOUDFLARED_TOKEN}\n\
         ExecStart=\n\
         ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run\n",
        credential.display()
    )
}

/// Seal the token and install the drop-in. Returns the drop-in's path.
fn install_cloudflared_token(paths: &Paths, sealer: &dyn Sealer, token: &Credential) -> Result<PathBuf> {
    let credential = paths
        .secret_store()
        .put(sealer, CLOUDFLARED_TOKEN, token.0.as_bytes())?;
    let drop_in = paths.drop_in(CLOUDFLARED);
    install_drop_in(&drop_in, &cloudflared_drop_in(&credential), false)?;
    Ok(drop_in)
}

fn cloudflared_set_token(
    paths: &Paths,
    sealer: &dyn Sealer,
    token: &Credential,
    dry_run: bool,
) -> Result<Value> {
    validate_credential("tunnel token", token)?;
    let drop_in = if dry_run {
        paths.drop_in(CLOUDFLARED)
    } else {
        install_cloudflared_token(paths, sealer, token)?
    };
    let mut commands = Commands::new(dry_run);
    commands.run("systemctl", &["daemon-reload"])?;
    commands.run("systemctl", &["enable", CLOUDFLARED])?;
    // Restart, so a new token replaces a running tunnel.
    commands.run("systemctl", &["restart", CLOUDFLARED])?;
    Ok(jsonf! { "enabled": true, drop_in, dry_run, "commands": commands.done })
}

fn cloudflared_disable(paths: &Paths, dry_run: bool) -> Result<Value> {
    let mut commands = Commands::new(dry_run);
    // Fails when cloudflared is not installed; clean up anyway.
    let disabled =
        commands.run_ignoring_failure("systemctl", &["disable", "--now", CLOUDFLARED]);
    if !dry_run {
        store::remove(&paths.drop_in(CLOUDFLARED))?;
        paths.secret_store().remove(CLOUDFLARED_TOKEN)?;
    }
    commands.run("systemctl", &["daemon-reload"])?;
    let enabled = !disabled && unit_enabled(CLOUDFLARED);
    Ok(jsonf! { enabled, dry_run, "commands": commands.done })
}

fn unit_active(unit: &str) -> bool {
    crate::cmd!("systemctl" ["is-active", "--quiet", unit]).is_ok()
}

fn status() -> Value {
    let mut tailscale = jsonf! { "enabled": unit_enabled(TAILSCALED), "serve": false, "funnel": false };
    if unit_active(TAILSCALED) {
        if let Some(serve) = crate::cmd!("tailscale" ["serve", "status", "--json"])
            .ok()
            .and_then(|result| serde_json::from_str(&result.stdout).ok())
        {
            let (serve, funnel) = serve_state(&serve);
            tailscale["serve"] = serve.into();
            tailscale["funnel"] = funnel.into();
        }
        if let Some(hostname) = current_tailnet_hostname() {
            tailscale["hostname"] = hostname.into();
        }
    }
    jsonf! {
        tailscale,
        "cloudflared": { "enabled": unit_enabled(CLOUDFLARED) },
    }
}

/// Whether `tailscale serve status --json` shows anything served, and
/// whether any of it is funneled.
fn serve_state(status: &Value) -> (bool, bool) {
    let non_empty = |key: &str| {
        status
            .get(key)
            .and_then(Value::as_object)
            .is_some_and(|map| !map.is_empty())
    };
    let funnel = status
        .get("AllowFunnel")
        .and_then(Value::as_object)
        .is_some_and(|map| map.values().any(|allowed| allowed == &Value::Bool(true)));
    (non_empty("TCP") || non_empty("Web") || funnel, funnel)
}

/// This node's `MagicDNS` name, if tailscaled is up and logged in.
fn current_tailnet_hostname() -> Option<String> {
    crate::cmd!("tailscale" ["status", "--json", "--self"])
        .ok()
        .and_then(|result| serde_json::from_str(&result.stdout).ok())
        .and_then(|status: Value| tailnet_hostname(&status))
}

/// This node's `MagicDNS` name from `tailscale status --json`.
fn tailnet_hostname(status: &Value) -> Option<String> {
    status["Self"]["DNSName"]
        .as_str()
        .map(|name| name.trim_end_matches('.').to_owned())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use serde_json::json;

    use super::*;
    use crate::auth::testing::FakeSealer;

    const KEY: &str = "tskey-auth-kSECRET-0123456789abcdef";
    const TOKEN: &str = "eyJhIjoiU0VDUkVUIn0";

    fn paths(root: &Path) -> Paths {
        Paths {
            secrets: root.join("var/lib/tetra/secrets"),
            run_dir: root.join("run/tetra"),
            systemd_dir: root.join("etc/systemd/system"),
            access: root.join("var/lib/tetra/access.json"),
        }
    }

    fn commands(response: &Value) -> Vec<String> {
        response["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["command"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn tailscale_up_serves_by_default_and_never_puts_the_key_on_a_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let key = Credential(KEY.into());
        let response = tailscale_up(&paths, &key, true, false, true).unwrap();
        let mut commands = commands(&response);
        // A file of this call's own: `tailscale-auth-key-<pid>-<random>`.
        // `up`, `serve` and `funnel` can wait forever; each has a limit.
        let up = commands.remove(3);
        let key_file = up
            .strip_prefix("tailscale up --timeout=60s --auth-key=file:")
            .unwrap()
            .strip_prefix(&format!("{}/", paths.run_dir.display()))
            .unwrap();
        assert!(
            key_file.starts_with(&format!("tailscale-auth-key-{}-", std::process::id())),
            "{key_file}"
        );
        assert_eq!(
            commands,
            [
                "systemctl daemon-reload",
                "systemctl enable tailscaled.service",
                "systemctl restart tailscaled.service",
                "tailscale serve reset",
                "timeout 60s tailscale serve --bg --tcp=443 tcp://127.0.0.1:443",
            ]
        );
        assert_eq!(response["serve"], true);
        assert_eq!(response["funnel"], false);
        assert!(!response.to_string().contains(KEY));
        // A dry run writes nothing, and the key is never stored.
        assert!(!paths.secrets.exists());
        assert!(!paths.run_dir.exists());
        assert!(!paths.drop_in(TAILSCALED).exists());
    }

    #[test]
    fn the_auth_key_file_is_new_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        write_key_file(&path, &Credential(KEY.into())).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), KEY);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // An existing file (or a planted symlink) is never written through.
        write_key_file(&path, &Credential(KEY.into())).unwrap_err();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("target"), &link).unwrap();
        write_key_file(&link, &Credential(KEY.into())).unwrap_err();
        assert!(!dir.path().join("target").exists());
    }

    #[test]
    fn an_unreadable_access_file_is_an_error_not_port_443() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        assert_eq!(caddy_port(&paths.access).unwrap(), 443);
        fs::create_dir_all(paths.access.parent().unwrap()).unwrap();
        fs::write(&paths.access, "not json").unwrap();
        caddy_port(&paths.access).unwrap_err();
        // Fails before running anything, and so does a preview.
        let key = Credential(KEY.into());
        for dry_run in [false, true] {
            let error = tailscale_up(&paths, &key, true, false, dry_run).unwrap_err();
            assert!(format!("{error:#}").contains("dashboard's port"), "{error:#}");
        }
    }

    #[test]
    fn caddy_may_fetch_the_tailnet_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        assert!(install_drop_in(&paths.drop_in(TAILSCALED), TAILSCALED_DROP_IN, false).unwrap());
        let drop_in = paths.systemd_dir.join("tailscaled.service.d/50-tetra.conf");
        assert_eq!(
            fs::read_to_string(&drop_in).unwrap(),
            "# Managed by Tetra (remote_access.tailscale_up).\n[Service]\n\
             Environment=TS_PERMIT_CERT_UID=caddy\n"
        );
        // Once it is in place tailscaled is not restarted again.
        let key = Credential(KEY.into());
        let response = tailscale_up(&paths, &key, true, false, true).unwrap();
        assert_eq!(
            commands(&response)[0],
            "systemctl enable --now tailscaled.service"
        );

        let response = tailscale_disable(&paths, true).unwrap();
        assert_eq!(
            commands(&response),
            [
                "tailscale serve reset",
                "systemctl disable --now tailscaled.service",
                "systemctl daemon-reload",
            ]
        );
    }

    #[test]
    fn the_serve_default_and_funnel_are_explicit() {
        let payload: TailscaleUp =
            serde_json::from_value(json!({"auth_key": KEY})).unwrap();
        assert!(payload.serve);
        assert!(!payload.funnel);
        assert!(!format!("{payload:?}").contains(KEY));

        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let key = Credential(KEY.into());
        let funnel = tailscale_up(&paths, &key, true, true, true).unwrap();
        assert_eq!(
            commands(&funnel).last().unwrap(),
            "timeout 60s tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443"
        );
        let neither = tailscale_up(&paths, &key, false, false, true).unwrap();
        assert_eq!(commands(&neither).last().unwrap(), "tailscale serve reset");
        assert_eq!(neither["serve"], false);
    }

    #[test]
    fn tailscale_forwards_the_port_caddy_serves_the_dashboard_on() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let key = Credential(KEY.into());
        for (port, funnel_allowed) in [(8443, true), (9443, false)] {
            let request: crate::auth::access::AccessRequest = serde_json::from_value(json!({
                "mode": "domain", "hostname": "server.tail1234.ts.net", "port": port
            }))
            .unwrap();
            let mut access = AccessConfig::from_request(
                &request,
                crate::auth::access::DEFAULT_DASHBOARD_UPSTREAM,
            )
            .unwrap();
            access.save(&paths.access).unwrap();

            let served = tailscale_up(&paths, &key, true, false, true).unwrap();
            assert_eq!(
                commands(&served).last().unwrap(),
                &format!("timeout 60s tailscale serve --bg --tcp={port} tcp://127.0.0.1:{port}")
            );
            // Funnel publishes only 443, 8443 and 10000.
            let funneled = tailscale_up(&paths, &key, true, true, true);
            assert_eq!(funneled.is_ok(), funnel_allowed, "{port}");
        }
    }

    #[test]
    fn credentials_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        for bad in ["", "tskey with space", "tskey\n--advertise-exit-node"] {
            tailscale_up(&paths, &Credential(bad.into()), true, false, true).unwrap_err();
            cloudflared_set_token(&paths, &FakeSealer, &Credential(bad.into()), true).unwrap_err();
        }
    }

    #[test]
    fn cloudflared_token_is_sealed_and_loaded_as_a_systemd_credential() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let drop_in = install_cloudflared_token(&paths, &FakeSealer, &Credential(TOKEN.into()))
            .unwrap();
        assert_eq!(
            drop_in,
            paths
                .systemd_dir
                .join("cloudflared.service.d/50-tetra.conf")
        );
        let unit = fs::read_to_string(&drop_in).unwrap();
        let credential = paths.secrets.join("tetra-cloudflared-token.cred");
        assert!(unit.contains(&format!(
            "LoadCredentialEncrypted=tetra-cloudflared-token:{}\n",
            credential.display()
        )));
        assert!(unit.contains("Environment=TUNNEL_TOKEN_FILE=%d/tetra-cloudflared-token\n"));
        assert!(unit.contains("ExecStart=\nExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run\n"));
        assert!(!unit.contains(TOKEN));
        // Sealed under the credential name systemd checks it against.
        assert_eq!(
            FakeSealer
                .unseal(CLOUDFLARED_TOKEN, &fs::read(&credential).unwrap())
                .unwrap(),
            TOKEN.as_bytes()
        );
        assert_eq!(
            fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn cloudflared_set_token_restarts_the_tunnel_and_disable_forgets_it() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let response =
            cloudflared_set_token(&paths, &FakeSealer, &Credential(TOKEN.into()), true).unwrap();
        assert_eq!(
            commands(&response),
            [
                "systemctl daemon-reload",
                "systemctl enable cloudflared.service",
                "systemctl restart cloudflared.service",
            ]
        );
        assert!(!response.to_string().contains(TOKEN));

        install_cloudflared_token(&paths, &FakeSealer, &Credential(TOKEN.into())).unwrap();
        let response = cloudflared_disable(&paths, true).unwrap();
        assert_eq!(
            commands(&response),
            [
                "systemctl disable --now cloudflared.service",
                "systemctl daemon-reload",
            ]
        );
        assert_eq!(response["enabled"], false);
        // A dry run leaves the files alone.
        assert!(paths.drop_in(CLOUDFLARED).exists());
    }

    #[test]
    fn tailscale_disable_resets_serve_and_stops_tailscaled() {
        let dir = tempfile::tempdir().unwrap();
        let response = tailscale_disable(&paths(dir.path()), true).unwrap();
        assert_eq!(
            commands(&response),
            [
                "tailscale serve reset",
                "systemctl disable --now tailscaled.service",
            ]
        );
        assert_eq!(response["enabled"], false);
    }

    #[test]
    fn reads_serve_and_funnel_state() {
        assert_eq!(serve_state(&json!({})), (false, false));
        let served = json!({
            "TCP": {"443": {"HTTPS": true}},
            "Web": {"server.tail1234.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3972"}}}}
        });
        assert_eq!(serve_state(&served), (true, false));
        let mut funneled = served;
        funneled["AllowFunnel"] = json!({"server.tail1234.ts.net:443": true});
        assert_eq!(serve_state(&funneled), (true, true));
        assert_eq!(
            tailnet_hostname(&json!({"Self": {"DNSName": "server.tail1234.ts.net."}})),
            Some("server.tail1234.ts.net".into())
        );
        assert_eq!(tailnet_hostname(&json!({})), None);
    }

    #[test]
    fn status_takes_null_or_an_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        for payload in [Value::Null, json!({})] {
            let response = handle(&paths, "status", payload).unwrap();
            assert!(response["tailscale"]["enabled"].is_boolean(), "{response}");
        }
    }

    #[test]
    fn a_failed_tailscale_up_undoes_only_what_it_set_up() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let drop_in = paths.drop_in(TAILSCALED);
        let undo = |was_running, had_drop_in| {
            let mut commands = Commands::fake(false, "");
            undo_tailscale_up(&paths, was_running, had_drop_in, &mut commands).unwrap();
            commands
                .done
                .iter()
                .map(|command| command["command"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };

        // tailscaled was off and the drop-in new: both are undone.
        assert!(install_drop_in(&drop_in, TAILSCALED_DROP_IN, false).unwrap());
        assert_eq!(
            undo(false, false),
            ["systemctl disable --now tailscaled.service", "systemctl daemon-reload"]
        );
        assert!(!drop_in.exists());

        // Both were there before: neither is touched.
        assert!(install_drop_in(&drop_in, TAILSCALED_DROP_IN, false).unwrap());
        assert_eq!(undo(true, true), Vec::<String>::new());
        assert!(drop_in.exists());
    }

    #[test]
    fn disabling_takes_no_payload() {
        // Parsed only: handling it would disable the host's services.
        for action in ["tailscale_disable", "cloudflared_disable"] {
            let action: Action = parse_action(action, Value::Null).unwrap();
            assert!(matches!(
                action,
                Action::TailscaleDisable(Disable { dry_run: false })
                    | Action::CloudflaredDisable(Disable { dry_run: false })
            ));
        }
    }

    #[test]
    fn every_action_but_capabilities_is_privileged() {
        for action in INFO.actions {
            if !matches!(*action, "capabilities" | "plan") {
                assert!(INFO.is_privileged(action), "{action}");
            }
        }
    }
}
