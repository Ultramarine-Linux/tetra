//! Remote access to the dashboard: Tailscale and Cloudflare Tunnel.
//!
//! Both ship disabled (`tailscaled.service`, `cloudflared.service`). These
//! actions turn them on and off. Their credentials are sealed in Tetra's
//! secret store ([`crate::auth::secrets`]) and handed to the services without
//! ever appearing on a command line, in a unit file or in a log:
//!
//! - `tailscale_up` writes the auth key to a root-only file under `/run/tetra`
//!   just long enough for `tailscale up --auth-key=file:<path>`. By default it
//!   then shares Caddy's HTTPS port on the tailnet with `tailscale serve`;
//!   with `funnel: true` (never by default) it publishes it on the internet
//!   with `tailscale funnel` instead. Both forward raw TCP to Caddy, so the
//!   dashboard, apps, the public page and forward-auth behave as on the LAN
//!   once `access.set` uses this node's `*.ts.net` name as the hostname.
//!   Caddy gets that name's certificate from tailscaled, which a
//!   `tailscaled.service` drop-in allows for the `caddy` user
//!   (`TS_PERMIT_CERT_UID`).
//! - `cloudflared_set_token` stores the tunnel token as an encrypted systemd
//!   credential and installs a `cloudflared.service` drop-in that loads it
//!   (`LoadCredentialEncrypted=`) and points `TUNNEL_TOKEN_FILE` at it, so
//!   only the running service sees the plain token.
//!
//! `tailscale_disable` and `cloudflared_disable` stop and disable the service
//! and forget the credential.

use std::os::unix::fs::PermissionsExt as _;

use crate::prelude::*;

use crate::auth::{
    access::{AccessConfig, HTTPS_PORT},
    seal::{Sealer, SystemdCreds},
    secrets::{CLOUDFLARED_TOKEN, DEFAULT_SECRETS_DIR, SecretStore, TAILSCALE_AUTH_KEY},
    store,
};

/// Marker type for the remote access module.
#[derive(Clone, Copy, Debug)]
pub struct RemoteAccessModule;

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
const DROP_IN_NAME: &str = "50-tetra.conf";
const TAILSCALE_KEY_FILE: &str = "tailscale-auth-key";
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
    fn default() -> Self {
        Self {
            secrets: DEFAULT_SECRETS_DIR.into(),
            run_dir: "/run/tetra".into(),
            systemd_dir: "/etc/systemd/system".into(),
            access: "/var/lib/tetra/access.json".into(),
        }
    }
}

impl Paths {
    fn secret_store(&self) -> SecretStore {
        SecretStore::new(self.secrets.clone())
    }

    fn tailscaled_drop_in(&self) -> PathBuf {
        self.systemd_dir.join(format!("{TAILSCALED}.d")).join(DROP_IN_NAME)
    }

    fn cloudflared_drop_in(&self) -> PathBuf {
        self.systemd_dir
            .join(format!("{CLOUDFLARED}.d"))
            .join(DROP_IN_NAME)
    }
}

impl Mod for RemoteAccessModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        if let Some(response) = INFO.metadata_response(action, &payload) {
            return Ok(response);
        }
        Action::from_payload(action, payload)?.handle(user)
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

const fn default_true() -> bool {
    true
}

actions!(Action [payload user] => {
    Status => Ok(status()),
    TailscaleUp {
        auth_key: Credential,
        /// Share Caddy on the tailnet (`tailscale serve`).
        #[serde(default = "default_true")]
        serve: bool,
        /// Publish Caddy on the internet (`tailscale funnel`).
        /// Only when explicitly set.
        #[serde(default)]
        funnel: bool,
        #[serde(default)]
        dry_run: bool,
    } => tailscale_up(
        &Paths::default(),
        &SystemdCreds,
        &payload.auth_key,
        payload.serve,
        payload.funnel,
        payload.dry_run,
    ),
    TailscaleDisable {
        #[serde(default)]
        dry_run: bool,
    } => tailscale_disable(&Paths::default(), payload.dry_run),
    CloudflaredSetToken {
        token: Credential,
        #[serde(default)]
        dry_run: bool,
    } => cloudflared_set_token(&Paths::default(), &SystemdCreds, &payload.token, payload.dry_run),
    CloudflaredDisable {
        #[serde(default)]
        dry_run: bool,
    } => cloudflared_disable(&Paths::default(), payload.dry_run),
});

/// Commands run (or planned) by one action, in order.
struct Commands {
    dry_run: bool,
    done: Vec<Value>,
}

impl Commands {
    const fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            done: Vec::new(),
        }
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<()> {
        let result =
            crate::agent::module_support::run_command_output_as(program, args, self.dry_run, None)?;
        self.done.push(serde_json::to_value(result)?);
        Ok(())
    }

    /// Run a command whose failure does not stop the action (cleanup of
    /// state that may not exist).
    fn run_ignoring_failure(&mut self, program: &str, args: &[&str]) {
        if let Err(error) = self.run(program, args) {
            self.done
                .push(jsonf! { "command": crate::agent::module_support::command_display(program, args), "error": error.to_string() });
        }
    }
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
/// so the dashboard's origin is the same on the tailnet.
fn caddy_port(access: &Path) -> u16 {
    AccessConfig::load(access)
        .ok()
        .flatten()
        .and_then(|access| access.port)
        .unwrap_or(HTTPS_PORT)
}

/// Install the `tailscaled.service` drop-in, returning whether it changed.
fn install_tailscaled_drop_in(paths: &Paths, dry_run: bool) -> Result<bool> {
    let drop_in = paths.tailscaled_drop_in();
    if fs::read(&drop_in).ok().as_deref() == Some(TAILSCALED_DROP_IN.as_bytes()) {
        return Ok(false);
    }
    if !dry_run {
        let dir = drop_in.parent().context("drop-in has no parent")?;
        fs::create_dir_all(dir).with_context(|| format!("failed to create `{}`", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
        store::replace(&drop_in, TAILSCALED_DROP_IN.as_bytes(), 0o644)?;
    }
    Ok(true)
}

fn tailscale_up(
    paths: &Paths,
    sealer: &dyn Sealer,
    auth_key: &Credential,
    serve: bool,
    funnel: bool,
    dry_run: bool,
) -> Result<Value> {
    validate_credential("auth key", auth_key)?;
    let port = caddy_port(&paths.access);
    ensure!(
        !funnel || FUNNEL_PORTS.contains(&port),
        "Tailscale Funnel only publishes ports 443, 8443 and 10000, and the dashboard is on {port}"
    );
    let mut commands = Commands::new(dry_run);
    if !dry_run {
        paths
            .secret_store()
            .put(sealer, TAILSCALE_AUTH_KEY, auth_key.0.as_bytes())?;
    }
    if install_tailscaled_drop_in(paths, dry_run)? {
        // A running tailscaled only picks up the new environment on restart.
        commands.run("systemctl", &["daemon-reload"])?;
        commands.run("systemctl", &["enable", TAILSCALED])?;
        commands.run("systemctl", &["restart", TAILSCALED])?;
    } else {
        commands.run("systemctl", &["enable", "--now", TAILSCALED])?;
    }

    let key_file = paths.run_dir.join(TAILSCALE_KEY_FILE);
    let key_arg = format!("--auth-key=file:{}", key_file.display());
    if !dry_run {
        fs::create_dir_all(&paths.run_dir)
            .with_context(|| format!("failed to create `{}`", paths.run_dir.display()))?;
        store::replace(&key_file, auth_key.0.as_bytes(), 0o600)?;
    }
    let up = commands.run("tailscale", &["up", &key_arg]);
    if !dry_run {
        store::remove(&key_file)?;
    }
    up?;

    // Start from a clean serve configuration so turning serve or funnel off
    // takes effect.
    commands.run("tailscale", &["serve", "reset"])?;
    // Raw TCP, so Caddy terminates TLS and routes by name as on the LAN.
    let tcp = format!("--tcp={port}");
    let target = format!("tcp://127.0.0.1:{port}");
    if funnel {
        commands.run("tailscale", &["funnel", "--bg", &tcp, &target])?;
    } else if serve {
        commands.run("tailscale", &["serve", "--bg", &tcp, &target])?;
    }
    // The name the OOBE should give `access.set`.
    let hostname = if dry_run {
        None
    } else {
        crate::cmd!("tailscale" ["status", "--json", "--self"])
            .ok()
            .and_then(|result| serde_json::from_str(&result.stdout).ok())
            .and_then(|status: Value| tailnet_hostname(&status))
    };
    Ok(jsonf! {
        "enabled": true,
        "serve": serve || funnel,
        funnel,
        target,
        hostname,
        dry_run,
        "commands": commands.done,
    })
}

fn tailscale_disable(paths: &Paths, dry_run: bool) -> Result<Value> {
    let mut commands = Commands::new(dry_run);
    // Fails when tailscaled is not running; nothing to reset then.
    commands.run_ignoring_failure("tailscale", &["serve", "reset"]);
    commands.run("systemctl", &["disable", "--now", TAILSCALED])?;
    let drop_in = paths.tailscaled_drop_in();
    if drop_in.exists() {
        if !dry_run {
            store::remove(&drop_in)?;
        }
        commands.run("systemctl", &["daemon-reload"])?;
    }
    if !dry_run {
        paths.secret_store().remove(TAILSCALE_AUTH_KEY)?;
    }
    Ok(jsonf! { "enabled": false, dry_run, "commands": commands.done })
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
    let drop_in = paths.cloudflared_drop_in();
    let dir = drop_in.parent().context("drop-in has no parent")?;
    fs::create_dir_all(dir).with_context(|| format!("failed to create `{}`", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    store::replace(&drop_in, cloudflared_drop_in(&credential).as_bytes(), 0o644)?;
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
        paths.cloudflared_drop_in()
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
    commands.run("systemctl", &["disable", "--now", CLOUDFLARED])?;
    if !dry_run {
        store::remove(&paths.cloudflared_drop_in())?;
        paths.secret_store().remove(CLOUDFLARED_TOKEN)?;
    }
    commands.run("systemctl", &["daemon-reload"])?;
    Ok(jsonf! { "enabled": false, dry_run, "commands": commands.done })
}

fn unit_enabled(unit: &str) -> bool {
    crate::cmd!("systemctl" ["is-enabled", unit])
        .is_ok_and(|result| result.stdout.trim() == "enabled")
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
        if let Some(hostname) = crate::cmd!("tailscale" ["status", "--json", "--self"])
            .ok()
            .and_then(|result| serde_json::from_str(&result.stdout).ok())
            .and_then(|status: Value| tailnet_hostname(&status))
        {
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

/// This node's `MagicDNS` name from `tailscale status --json`.
fn tailnet_hostname(status: &Value) -> Option<String> {
    status["Self"]["DNSName"]
        .as_str()
        .map(|name| name.trim_end_matches('.').to_owned())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
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
        let response = tailscale_up(&paths, &FakeSealer, &key, true, false, true).unwrap();
        let key_file = paths.run_dir.join(TAILSCALE_KEY_FILE);
        assert_eq!(
            commands(&response),
            [
                "systemctl daemon-reload".to_owned(),
                "systemctl enable tailscaled.service".to_owned(),
                "systemctl restart tailscaled.service".to_owned(),
                format!("tailscale up --auth-key=file:{}", key_file.display()),
                "tailscale serve reset".to_owned(),
                "tailscale serve --bg --tcp=443 tcp://127.0.0.1:443".to_owned(),
            ]
        );
        assert_eq!(response["serve"], true);
        assert_eq!(response["funnel"], false);
        assert!(!response.to_string().contains(KEY));
        // A dry run stores nothing.
        assert!(!paths.secrets.exists());
        assert!(!key_file.exists());
        assert!(!paths.tailscaled_drop_in().exists());
    }

    #[test]
    fn caddy_may_fetch_the_tailnet_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        assert!(install_tailscaled_drop_in(&paths, false).unwrap());
        let drop_in = paths.systemd_dir.join("tailscaled.service.d/50-tetra.conf");
        assert_eq!(
            fs::read_to_string(&drop_in).unwrap(),
            "# Managed by Tetra (remote_access.tailscale_up).\n[Service]\n\
             Environment=TS_PERMIT_CERT_UID=caddy\n"
        );
        // Once it is in place tailscaled is not restarted again.
        let key = Credential(KEY.into());
        let response = tailscale_up(&paths, &FakeSealer, &key, true, false, true).unwrap();
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
        let funnel = tailscale_up(&paths, &FakeSealer, &key, true, true, true).unwrap();
        assert_eq!(
            commands(&funnel).last().unwrap(),
            "tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443"
        );
        let neither = tailscale_up(&paths, &FakeSealer, &key, false, false, true).unwrap();
        assert_eq!(commands(&neither).last().unwrap(), "tailscale serve reset");
        assert_eq!(neither["serve"], false);
    }

    #[test]
    fn tailscale_forwards_the_port_caddy_serves_the_dashboard_on() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let key = Credential(KEY.into());
        for (port, funnel_allowed) in [(8443, true), (9443, false)] {
            let mut access = AccessConfig::from_request(
                serde_json::from_value(json!({
                    "mode": "domain", "hostname": "server.tail1234.ts.net", "port": port
                }))
                .unwrap(),
                crate::auth::access::DEFAULT_DASHBOARD_UPSTREAM,
            )
            .unwrap();
            access.save(&paths.access).unwrap();

            let served = tailscale_up(&paths, &FakeSealer, &key, true, false, true).unwrap();
            assert_eq!(
                commands(&served).last().unwrap(),
                &format!("tailscale serve --bg --tcp={port} tcp://127.0.0.1:{port}")
            );
            // Funnel publishes only 443, 8443 and 10000.
            let funneled = tailscale_up(&paths, &FakeSealer, &key, true, true, true);
            assert_eq!(funneled.is_ok(), funnel_allowed, "{port}");
        }
    }

    #[test]
    fn credentials_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        for bad in ["", "tskey with space", "tskey\n--advertise-exit-node"] {
            tailscale_up(&paths, &FakeSealer, &Credential(bad.into()), true, false, true)
                .unwrap_err();
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
        // A dry run leaves the files alone.
        assert!(paths.cloudflared_drop_in().exists());
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
    fn every_action_but_capabilities_is_privileged() {
        for action in INFO.actions {
            if !matches!(*action, "capabilities" | "plan") {
                assert!(INFO.is_privileged(action), "{action}");
            }
        }
    }
}
