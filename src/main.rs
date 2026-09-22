use std::{
    fs,
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use tetra::{
    agent::{
        AgentCommand, backend,
        transport::TransportConfig,
        vsock::VsockAgentConfig,
        websocket::{self, WebSocketAgentConfig},
        websocket_server::{self, WebSocketServerConfig},
    },
    catalog::{RenderOptions, RenderedResource},
    enrollment,
};

/// Tetra CLI entry point.
///
/// The binary has two broad modes, exposed as subcommands:
///
/// - **Recipe rendering** (`render`) — pure local tooling that turns a YAML
///   recipe + Tera templates into container unit and companion files. No agent
///   backend, no transport.
/// - **Agent** (`agent-dispatch`, `agent-vsock-serve`, `agent-connect`,
///   `agent-ws-serve`) — the same Kameo-backed dispatcher exposed through
///   different surfaces: a one-shot CLI, a vsock smoke-test listener, an
///   outbound WSS control-plane connection, and an authenticated inbound
///   WebSocket for the dashboard.
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

    /// Dispatch one signed agent command envelope locally.
    AgentDispatch(AgentDispatchCli),

    /// Serve the local agent backend over a Linux virtio-vsock listener.
    AgentVsockServe(VsockAgentConfig),

    /// Connect the local agent backend to an outbound WSS control plane.
    AgentConnect(AgentConnectCli),

    /// Serve an authenticated WebSocket for a dashboard client.
    AgentWsServe(AgentWsServeCli),

    /// Enroll this host with an Ultramarine Dashboard.
    Enroll(EnrollCli),
}

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
struct AgentWsServeCli {
    /// Loopback address for the WebSocket listener.
    #[arg(long, default_value = "127.0.0.1:7780")]
    listen: SocketAddr,

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
    /// Dashboard base URL.
    #[arg(long, env = "TETRA_DASHBOARD_URL")]
    dashboard_url: Option<String>,

    /// Public WSS URL where Dashboard can reach this host.
    #[arg(long)]
    agent_url: Option<String>,

    /// Local address and port for the Tetra WebSocket listener.
    #[arg(long)]
    listen: Option<String>,

    /// Dashboard display name for this host.
    #[arg(long)]
    display_name: Option<String>,

    /// Write device authorization details to this file as soon as they are created.
    #[arg(long)]
    approval_file: Option<PathBuf>,

    /// Browser-reachable base URL to use when printing the approval link.
    #[arg(long)]
    verification_url: Option<String>,

    #[arg(long, default_value = "/var/lib/tetra/identity")]
    identity_dir: String,

    #[arg(long, default_value = "/etc/tetra")]
    config_dir: String,

    #[arg(long)]
    hostname: Option<String>,

    /// Permit plaintext/local development endpoints and invalid Dashboard TLS.
    #[arg(long)]
    insecure: bool,

    /// Do not call systemctl after approval (useful in containers and OOBE).
    #[arg(long)]
    skip_service: bool,
}

#[derive(Debug, Parser)]
struct AgentConnectCli {
    /// JSON transport config containing `control_plane_url` and optional TLS paths.
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Stable dashboard host id for this agent.
    #[arg(long, env = "TETRA_HOST_ID")]
    host_id: String,

    /// Reconnect with exponential backoff when the control-plane session closes.
    #[arg(long, default_value_t = true)]
    reconnect: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Render(cli) => render(cli),
        Commands::AgentDispatch(cli) => agent_dispatch(cli).await,
        Commands::AgentVsockServe(cli) => cli.serve(),
        Commands::AgentConnect(cli) => agent_connect(cli).await,
        Commands::AgentWsServe(cli) => agent_ws_serve(cli).await,
        Commands::Enroll(cli) => {
            enrollment::run(enrollment::Options {
                dashboard_url: cli.dashboard_url,
                agent_url: cli.agent_url,
                listen: cli.listen,
                display_name: cli.display_name,
                approval_file: cli.approval_file,
                verification_url: cli.verification_url,
                identity_dir: cli.identity_dir,
                config_dir: cli.config_dir,
                hostname: cli.hostname,
                insecure: cli.insecure,
                skip_service: cli.skip_service,
            })
            .await
        }
    }
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
    websocket_server::WebSocketServerConfig::serve(WebSocketServerConfig {
        listen,
        controller_public_key,
        enrollment_token,
        identity_dir,
        tls_cert_key_path: tls_cert.zip(tls_key),
    })
    .await
}

async fn agent_connect(cli: AgentConnectCli) -> Result<()> {
    let text = fs::read_to_string(&cli.config)
        .with_context(|| format!("failed to read config `{}`", cli.config.display()))?;
    let transport: TransportConfig =
        serde_json::from_str(&text).context("failed to parse transport config JSON")?;

    websocket::run(WebSocketAgentConfig {
        transport,
        host_id: cli.host_id,
        reconnect: cli.reconnect,
    })
    .await
}
