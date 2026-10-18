use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::watch;

use tetra::{
    agent::{
        AgentBackend, AgentCommand, backend,
        config::{self, RuntimeConfig},
        crypto::public_key_fingerprint,
        identity::HostIdentity,
        local_protocol::LocalServer,
        local_socket,
        peer::{self, PeerPolicy},
        queue::{DEFAULT_QUEUE_CAPACITY, DispatchQueue},
        remote,
        transport::TransportConfig,
        vsock::VsockAgentConfig,
        websocket::WebSocketAgentConfig,
    },
    auth::{
        self, AuthConfig, AuthService, Backends,
        access::DEFAULT_DASHBOARD_UPSTREAM,
        accounts::{DEFAULT_EXCLUDED, LoginPolicy, SystemAccounts},
        audit::{self as action_log, AuditLog},
        clock::SystemClock,
        pam::{self as tetra_pam, LibPam},
        seal::SystemdCreds,
    },
    catalog::{RenderOptions, RenderedResource},
    enrollment::{self, store::DEFAULT_ENROLLMENT_DIR, store::Enrollment},
};

/// Tetra CLI entry point.
///
/// The binary has two broad modes, exposed as subcommands:
///
/// - **Recipe rendering** (`render`) — pure local tooling that turns a YAML
///   recipe + Tera templates into container unit and companion files. No agent
///   backend, no transport.
/// - **Agent** (`agent-serve`, `agent-dispatch`, `agent-vsock-serve`,
///   `agent-connect`, `agent-ws-serve`) — the same Kameo-backed dispatcher
///   exposed through different surfaces: the local Unix socket daemon, a
///   one-shot CLI, a vsock smoke-test listener, an outbound WSS control-plane
///   connection, and (with the `dev-listener` feature) a development TCP
///   WebSocket listener.
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Tetra agent and recipe tooling for managing hosts"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Render a Tetra app recipe into container unit files with Tera templates.
    Render(RenderCli),

    /// Run the host agent daemon, serving local clients over a Unix socket.
    AgentServe(AgentServeCli),

    /// Dispatch one signed agent command envelope locally.
    AgentDispatch(AgentDispatchCli),

    /// Serve the local agent backend over a Linux virtio-vsock listener.
    AgentVsockServe(VsockAgentConfig),

    /// Connect the local agent backend to an outbound WSS control plane.
    AgentConnect(AgentConnectCli),

    /// Serve an authenticated WebSocket over TCP (development only).
    #[cfg(feature = "dev-listener")]
    AgentWsServe(AgentWsServeCli),

    /// Enroll this host for outbound remote control (requires remote.enabled).
    Enroll(EnrollCli),

    /// Remove this host's remote-control certificate and controller record.
    Unenroll(UnenrollCli),

    /// Console recovery for dashboard logins (root only).
    #[command(subcommand)]
    Auth(AuthCommand),

    /// First-boot setup: show the setup code, or finish setup (root only).
    #[command(subcommand)]
    Setup(SetupCommand),
}

#[derive(Debug, Subcommand)]
enum SetupCommand {
    /// Publish the setup code to the console and print it.
    Code(SetupCodeCli),
    /// Finish setup without the OOBE, on a host that already has an eligible
    /// administrator (upgrades, development machines).
    Complete(SetupCompleteCli),
}

#[derive(Debug, Parser)]
struct SetupCompleteCli {
    /// Tetra state directory.
    #[arg(long, env = "TETRA_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Remove a user's TOTP and recovery codes and log out all their sessions.
    #[command(name = "reset-2fa")]
    ResetSecondFactor(ResetSecondFactorCli),
}

#[derive(Debug, Parser)]
struct ResetSecondFactorCli {
    /// Account name.
    user: String,

    /// Also remove the user's passkeys.
    #[arg(long)]
    passkeys: bool,

    /// Tetra state directory.
    #[arg(long, env = "TETRA_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
}

#[derive(Debug, Parser)]
struct SetupCodeCli {
    /// Do not print the code. It is always written to /run/tetra/setup-code
    /// and the getty banner (run at boot by tetra-setup-code.service).
    #[arg(long)]
    publish: bool,

    /// Tetra state directory.
    #[arg(long, env = "TETRA_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
}

/// Root-only state: credentials, grants, sessions, the setup marker.
const DEFAULT_STATE_DIR: &str = "/var/lib/tetra";

#[derive(Debug, Parser)]
struct RenderCli {
    /// Tetra recipe YAML.
    recipe: PathBuf,

    /// User values YAML for recipe parameters.
    #[arg(short, long)]
    values: Option<PathBuf>,

    /// Directory containing Tera templates referenced by the recipe.
    #[arg(short, long, value_name = "DIR")]
    templates_dir: PathBuf,

    /// Directory where rendered files should be written.
    #[arg(short, long, value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// Print rendered resources instead of writing them.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Parser)]
struct AgentDispatchCli {
    /// JSON command envelope to dispatch. Reads stdin when omitted.
    command: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct AgentServeCli {
    /// Runtime config (`remote.enabled`, ...). Re-read on SIGHUP.
    #[arg(long, env = "TETRA_CONFIG", default_value = config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Unix socket to bind when not started by systemd socket activation.
    #[arg(long, env = "TETRA_SOCKET", default_value = local_socket::DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Mutable identity directory. Defaults to /var/lib/tetra/identity.
    #[arg(long, default_value = "/var/lib/tetra/identity")]
    identity_dir: PathBuf,

    /// Root-only state directory for credentials, grants and sessions.
    #[arg(long, env = "TETRA_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,

    /// Account whose UID identifies the dashboard on the local socket.
    #[arg(long, env = "TETRA_DASHBOARD_USER", default_value = peer::DEFAULT_DASHBOARD_USER)]
    dashboard_user: String,

    /// Account whose UID identifies the server OOBE on the local socket.
    #[arg(long, env = "TETRA_OOBE_USER", default_value = peer::DEFAULT_OOBE_USER)]
    oobe_user: String,

    /// PAM service used to verify dashboard passwords.
    #[arg(long, default_value = tetra_pam::DEFAULT_SERVICE)]
    pam_service: String,

    /// Caddy site directory where `access.set` writes the dashboard site.
    #[arg(long, default_value = "/etc/caddy/tetra-sites")]
    caddy_sites_dir: PathBuf,

    /// Where the dashboard container listens, used for the dashboard's Caddy
    /// site when `access.set` does not name one. Must match the dashboard
    /// Quadlet's published port.
    #[arg(long, env = "TETRA_DASHBOARD_UPSTREAM", default_value = DEFAULT_DASHBOARD_UPSTREAM)]
    dashboard_upstream: String,

    /// Directory of the launcher's public page, which the dashboard's Caddy
    /// site serves under `/public/`. Must be readable by Caddy.
    #[arg(long, default_value = auth::launcher::DEFAULT_PUBLIC_DIR)]
    public_dir: PathBuf,

    /// Remote-control enrollment written by `tetra enroll`.
    #[arg(long, env = "TETRA_ENROLLMENT_DIR", default_value = DEFAULT_ENROLLMENT_DIR)]
    enrollment_dir: PathBuf,
}

#[cfg(feature = "dev-listener")]
#[derive(Debug, Parser)]
struct AgentWsServeCli {
    /// Loopback address for the WebSocket listener.
    #[arg(long, default_value = "127.0.0.1:7780")]
    listen: std::net::SocketAddr,

    /// URL-safe base64 Ed25519 public key enrolled for the dashboard controller.
    #[arg(long, env = "TETRA_CONTROLLER_PUBLIC_KEY")]
    controller_public_key: Option<String>,

    /// One-time token accepted to enroll a controller while no key is stored.
    #[arg(long, env = "TETRA_ENROLLMENT_TOKEN")]
    enrollment_token: Option<String>,

    /// Mutable identity directory. Defaults to /var/lib/tetra/identity.
    #[arg(long, default_value = "/var/lib/tetra/identity")]
    identity_dir: PathBuf,

    /// PEM certificate for WSS. Required with --tls-key for non-loopback binds.
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// PEM private key for WSS. Required with --tls-cert for non-loopback binds.
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct EnrollCli {
    /// Controller base URL that serves the enrollment API.
    #[arg(long, env = "TETRA_DASHBOARD_URL")]
    dashboard_url: Option<String>,

    /// Display name for this host on the controller.
    #[arg(long)]
    display_name: Option<String>,

    /// Write device authorization details to this file as soon as they are created.
    #[arg(long)]
    approval_file: Option<PathBuf>,

    /// Browser-reachable base URL to use when printing the approval link.
    #[arg(long)]
    verification_url: Option<String>,

    /// Runtime config; enrollment refuses to run unless `remote.enabled` is true.
    #[arg(long, env = "TETRA_CONFIG", default_value = config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Root-only directory for the client key, certificate and controller record.
    #[arg(long, env = "TETRA_ENROLLMENT_DIR", default_value = DEFAULT_ENROLLMENT_DIR)]
    enrollment_dir: PathBuf,

    #[arg(long)]
    hostname: Option<String>,

    /// Permit a plaintext controller URL and invalid controller TLS (development only).
    #[arg(long)]
    insecure: bool,

    /// Do not call systemctl after approval (useful in containers and OOBE).
    #[arg(long)]
    skip_service: bool,
}

#[derive(Debug, Parser)]
struct UnenrollCli {
    /// Directory written by `tetra enroll`.
    #[arg(long, env = "TETRA_ENROLLMENT_DIR", default_value = DEFAULT_ENROLLMENT_DIR)]
    enrollment_dir: PathBuf,

    /// Do not reload tetra.service after removing the enrollment.
    #[arg(long)]
    skip_service: bool,
}

#[derive(Debug, Parser)]
struct AgentConnectCli {
    /// JSON transport config containing `control_plane_url` and optional TLS
    /// paths. Defaults to the enrollment.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Stable control-plane host id for this agent. Defaults to the enrollment.
    #[arg(long, env = "TETRA_HOST_ID")]
    host_id: Option<String>,

    /// Remote-control enrollment written by `tetra enroll`.
    #[arg(long, env = "TETRA_ENROLLMENT_DIR", default_value = DEFAULT_ENROLLMENT_DIR)]
    enrollment_dir: PathBuf,

    /// Reconnect with exponential backoff when the control-plane session closes.
    #[arg(long, default_value_t = true)]
    reconnect: bool,

    /// Runtime config whose `remote.enabled` gates this connection. Re-read on SIGHUP.
    #[arg(long, env = "TETRA_CONFIG", default_value = config::DEFAULT_CONFIG_PATH)]
    runtime_config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Both rustls providers are compiled in (reqwest pulls in ring), so rustls
    // cannot pick one itself and would panic on first TLS use.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;

    match cli.command {
        Commands::Render(cli) => render(cli),
        Commands::AgentServe(cli) => agent_serve(cli).await,
        Commands::AgentDispatch(cli) => agent_dispatch(cli).await,
        Commands::AgentVsockServe(cli) => cli.serve(),
        Commands::AgentConnect(cli) => agent_connect(cli).await,
        #[cfg(feature = "dev-listener")]
        Commands::AgentWsServe(cli) => agent_ws_serve(cli).await,
        Commands::Enroll(cli) => {
            enrollment::run(enrollment::Options {
                dashboard_url: cli.dashboard_url,
                display_name: cli.display_name,
                approval_file: cli.approval_file,
                verification_url: cli.verification_url,
                runtime_config: cli.config,
                enrollment_dir: cli.enrollment_dir,
                hostname: cli.hostname,
                insecure: cli.insecure,
                skip_service: cli.skip_service,
            })
            .await
        }
        Commands::Unenroll(cli) => enrollment::unenroll(&enrollment::UnenrollOptions {
            enrollment_dir: cli.enrollment_dir,
            skip_service: cli.skip_service,
        }),
        Commands::Auth(AuthCommand::ResetSecondFactor(cli)) => reset_second_factor(&cli),
        Commands::Setup(SetupCommand::Code(cli)) => setup_code(cli),
        Commands::Setup(SetupCommand::Complete(cli)) => setup_complete(cli),
    }
}

fn require_root(what: &str) -> Result<()> {
    anyhow::ensure!(
        nix::unistd::geteuid().is_root(),
        "{what} must be run as root"
    );
    Ok(())
}

fn login_policy() -> Result<LoginPolicy> {
    LoginPolicy::load(
        "/etc/login.defs".as_ref(),
        "/etc/shells".as_ref(),
        DEFAULT_EXCLUDED
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
    )
}

fn system_auth(
    config: AuthConfig,
    pam_service: String,
    queue: DispatchQueue,
) -> Result<AuthService> {
    AuthService::new(
        config,
        Backends {
            accounts: Arc::new(SystemAccounts::default()),
            passwords: Arc::new(LibPam {
                service: pam_service,
            }),
            sealer: Arc::new(SystemdCreds),
            clock: Arc::new(SystemClock),
            policy: login_policy()?,
        },
        queue,
    )
}

fn reset_second_factor(cli: &ResetSecondFactorCli) -> Result<()> {
    require_root("tetra auth reset-2fa")?;
    let result = auth::service::reset_second_factor(
        &cli.state_dir,
        &SystemAccounts::default(),
        &cli.user,
        cli.passkeys,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// The auth service for a one-shot console command.
fn console_auth(state_dir: PathBuf) -> Result<AuthService> {
    let queue = DispatchQueue::spawn(AgentBackend::spawn_default(), 1);
    system_auth(
        AuthConfig::system(state_dir),
        tetra_pam::DEFAULT_SERVICE.into(),
        queue,
    )
}

fn setup_complete(cli: SetupCompleteCli) -> Result<()> {
    require_root("tetra setup complete")?;
    console_auth(cli.state_dir)?.complete_setup_from_console()?;
    println!("setup completed; the setup code is disabled");
    Ok(())
}

fn setup_code(cli: SetupCodeCli) -> Result<()> {
    require_root("tetra setup code")?;
    // Printing must not create a code that the console does not show, so
    // both forms publish; `--publish` (the boot unit) only skips printing it.
    match console_auth(cli.state_dir)?.publish_setup_code()? {
        Some(_) if cli.publish => eprintln!("published the setup code to the console"),
        Some(code) => println!("{code}"),
        None => eprintln!("setup is complete; there is no setup code"),
    }
    Ok(())
}

fn render(cli: RenderCli) -> Result<()> {
    let resources = RenderedResource::from_files(&RenderOptions {
        recipe_path: cli.recipe,
        values_path: cli.values,
        templates_dir: cli.templates_dir,
        output_dir: cli.output_dir,
        dry_run: cli.dry_run,
    })?;

    // In dry-run mode the renderer already skipped writes; print each resource
    // to stdout with a `--- filename` separator so the caller can preview what
    // would land on disk.
    if cli.dry_run {
        for resource in resources {
            println!("--- {}", resource.filename);
            print!("{}", resource.contents);
            if !resource.contents.ends_with('\n') {
                println!();
            }
        }
    }

    Ok(())
}

async fn agent_dispatch(cli: AgentDispatchCli) -> Result<()> {
    // Read the command envelope from either a path arg or stdin. Stdin lets
    // the agent be driven from a shell pipeline without a temp file.
    let text = if let Some(path) = cli.command {
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read command `{}`", path.display()))?
    } else {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .context("failed to read command from stdin")?;
        text
    };

    let command: AgentCommand =
        serde_json::from_str(&text).context("failed to parse agent command JSON")?;
    // Spawn a one-shot backend, dispatch, and print the response. The actor is
    // dropped when this future completes — no long-lived state survives the
    // CLI invocation, which is the right behavior for a one-shot dispatch.
    let response = backend::dispatch_with_default_backend(command).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// How often in-memory session activity is written to disk.
const SESSION_FLUSH_INTERVAL: Duration = Duration::from_mins(1);

async fn agent_serve(cli: AgentServeCli) -> Result<()> {
    let identity = HostIdentity::load_or_generate(&cli.identity_dir)?;
    let host_fingerprint = public_key_fingerprint(&identity.verifying_key());
    eprintln!("host identity: {}", identity.path().display());
    eprintln!("host fingerprint: {host_fingerprint}");

    let queue = DispatchQueue::spawn(AgentBackend::spawn_default(), DEFAULT_QUEUE_CAPACITY);
    let auth = system_auth(
        AuthConfig {
            caddy_sites_dir: cli.caddy_sites_dir,
            dashboard_upstream: cli.dashboard_upstream,
            public_dir: cli.public_dir,
            ..AuthConfig::system(cli.state_dir)
        },
        cli.pam_service,
        queue.clone(),
    )?;
    let audit = auth.audit();
    let server = LocalServer {
        auth: auth.clone(),
        peers: PeerPolicy::from_users(&cli.dashboard_user, &cli.oobe_user),
        host_fingerprint,
    };
    let listener = local_socket::listener(&cli.socket)?;
    peer::check_socket_group();

    let enrollment_dir = cli.enrollment_dir;
    let select = move |config: &RuntimeConfig| remote::connection_from(config, &enrollment_dir);
    let (sender, settings) = watch::channel(select(&RuntimeConfig::load_or_disabled(&cli.config)));
    // systemd stops the service with SIGTERM; both signals flush sessions.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install the SIGTERM handler")?;
    let result = tokio::select! {
        result = local_socket::serve(listener, server) => result,
        () = remote::supervise(settings, queue, audit) => Ok(()),
        result = remote::reload_on_hangup(cli.config, sender, select) => result,
        () = auth.flush_sessions_every(SESSION_FLUSH_INTERVAL) => Ok(()),
        result = tokio::signal::ctrl_c() => result.map_err(Into::into),
        _ = terminate.recv() => Ok(()),
    };
    auth.flush_sessions()?;
    result
}

#[cfg(feature = "dev-listener")]
async fn agent_ws_serve(
    AgentWsServeCli {
        listen,
        controller_public_key,
        enrollment_token,
        identity_dir,
        tls_cert,
        tls_key,
    }: AgentWsServeCli,
) -> Result<()> {
    anyhow::ensure!(
        tls_cert.as_ref().xor(tls_key.as_ref()).is_none(),
        "--tls-cert and --tls-key must be supplied together"
    );
    tetra::agent::dev_listener::WebSocketServerConfig::serve(
        tetra::agent::dev_listener::WebSocketServerConfig {
            listen,
            controller_public_key,
            enrollment_token,
            identity_dir,
            tls_cert_key_path: tls_cert.zip(tls_key),
        },
    )
    .await
}

async fn agent_connect(cli: AgentConnectCli) -> Result<()> {
    anyhow::ensure!(
        RuntimeConfig::load(&cli.runtime_config)?.remote.enabled,
        "remote control is disabled; set remote.enabled to true in `{}`",
        cli.runtime_config.display()
    );

    let transport = cli
        .config
        .map(|path| -> Result<TransportConfig> {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config `{}`", path.display()))?;
            serde_json::from_str(&text).context("failed to parse transport config JSON")
        })
        .transpose()?;
    // Re-resolved on every reload, so `tetra unenroll` drops the session.
    let resolve = move || -> Result<WebSocketAgentConfig> {
        let enrollment = Enrollment::load(&cli.enrollment_dir)?;
        let host_id = cli
            .host_id
            .clone()
            .or_else(|| {
                enrollment
                    .as_ref()
                    .map(|enrollment| enrollment.controller.host_id.clone())
            })
            .context("this host is not enrolled; run `tetra enroll` or pass --host-id")?;
        let transport = transport
            .clone()
            .or_else(|| enrollment.as_ref().map(Enrollment::transport))
            .context("this host is not enrolled; run `tetra enroll` or pass --config")?;
        Ok(WebSocketAgentConfig {
            transport,
            host_id,
            reconnect: cli.reconnect,
        })
    };

    let (sender, settings) = watch::channel(Some(resolve()?));
    let queue = DispatchQueue::spawn(AgentBackend::spawn_default(), DEFAULT_QUEUE_CAPACITY);
    let audit = AuditLog::new(action_log::DEFAULT_DIR.into());
    let select = move |config: &RuntimeConfig| {
        config
            .remote
            .enabled
            .then(&resolve)?
            .inspect_err(|error| {
                eprintln!("{error:#}; remote control disabled");
            })
            .ok()
    };
    tokio::select! {
        () = remote::supervise(settings, queue, audit) => Ok(()),
        result = remote::reload_on_hangup(cli.runtime_config, sender, select) => result,
    }
}
