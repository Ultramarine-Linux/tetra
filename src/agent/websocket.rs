use std::{env, fs::File, io::BufReader, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail};
use futures_util::{SinkExt, StreamExt};

use rand::RngExt;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};

use super::{
    AgentBackend, AgentCommand, AgentResponse,
    queue::{DEFAULT_QUEUE_CAPACITY, DispatchQueue, QueueError},
    transport::{TransportConfig, TransportEndpoint},
};

/// Protocol version advertised in the `Hello` frame. Bumped when the wire
/// format changes in a way the control plane must notice; the control plane
/// can refuse or warn on mismatched versions.
const PROTOCOL_VERSION: &str = "2026-06-29";
/// Upper bound for reconnect backoff. Without this a long partition could
/// push the delay into hours; capping at 60s keeps the agent responsive to a
/// control-plane restart.
const MAX_RECONNECT_DELAY: Duration = Duration::from_mins(1);

/// Configuration for the outbound WSS control-plane connection (`agent-connect`).
///
/// This is the production transport: the agent dials out to the control plane,
/// authenticates with mTLS, and exchanges [`TransportFrame`]s. Dialing out
/// (rather than listening) keeps the agent behind NAT/firewalls without port
/// forwarding — the same reason a Tailscale tailnet works.
#[derive(Debug, Clone)]
pub struct WebSocketAgentConfig {
    pub transport: TransportConfig,
    pub host_id: String,
    pub reconnect: bool,
}

/// The wire frame for the WSS control-plane protocol. Tagged with `type` so a
/// single `serde_json` parse dispatches on the frame kind.
///
/// The agent side only ever sends `Hello`, `Response`, `Pong`, and `Error`;
/// it receives `Command` and `Ping`. The other variants appear in this enum
/// so the deserialization round-trips frames the control plane might echo
/// back (and so `handle_frame` can explicitly reject them with an `Error`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TransportFrame {
    Hello {
        host_id: String,
        agent_version: String,
        protocol_version: String,
        hostname: Option<String>,
        os: String,
        arch: String,
    },
    Command {
        command: AgentCommand,
    },
    Response {
        response: AgentResponse,
    },
    Ping {
        id: Option<String>,
        sent_at: Option<String>,
    },
    Pong {
        id: Option<String>,
        sent_at: Option<String>,
    },
    Error {
        error: String,
    },
}

impl TransportFrame {
    /// Serialize and send one frame as a text message. We always send text (not
    /// binary) so the frames are easy to inspect in a proxy or log.
    async fn send<S>(&self, socket: &mut S) -> Result<()>
    where
        S: SinkExt<Message> + Unpin,
        <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
    {
        let text = serde_json::to_string(&self).context("failed to serialize websocket frame")?;
        socket
            .send(Message::Text(text.into()))
            .await
            .context("failed to send websocket frame")
    }

    /// Dispatch one received frame. `Command` frames go to the backend actor and
    /// the response is sent back as a `Response` frame; `Ping` is echoed as a
    /// `Pong`; anything else (including `Hello`, `Response`, `Pong`, `Error`) is
    /// rejected with an `Error` frame — the control plane should never send those
    /// to an agent.
    async fn handle<S>(self, socket: &mut S, queue: &DispatchQueue) -> Result<()>
    where
        S: SinkExt<Message> + Unpin,
        <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
    {
        match self {
            Self::Command { command } => match queue.dispatch(command).await {
                Ok(response) => Self::Response { response }.send(socket).await?,
                Err(QueueError::Full) => {
                    Self::Error {
                        error: "Tetra command queue is full; retry after backoff".into(),
                    }
                    .send(socket)
                    .await?;
                }
                Err(QueueError::Closed) => {
                    Self::Error {
                        error: "Tetra command queue is unavailable".into(),
                    }
                    .send(socket)
                    .await?;
                    bail!("dispatch queue closed")
                }
            },
            Self::Ping { id, sent_at } => {
                Self::Pong { id, sent_at }.send(socket).await?;
            }
            Self::Hello { .. } | Self::Response { .. } | Self::Pong { .. } | Self::Error { .. } => {
                Self::Error {
                    error: "unsupported frame from control plane".into(),
                }
                .send(socket)
                .await?;
            }
        }

        Ok(())
    }
}

/// Connect to the control plane, exchange frames until the session closes, and
/// (if `reconnect`) reconnect with backoff.
///
/// The outer loop is the reconnect loop; the inner [`connect_once`] is a single
/// session.
pub async fn run(config: WebSocketAgentConfig) -> Result<()> {
    let url = match config.transport.endpoint()? {
        TransportEndpoint::WebSocket { url } => url,
        TransportEndpoint::Vsock(_) => {
            bail!("agent-connect only supports ws:// and wss:// endpoints")
        }
    };

    config.transport.validate(&url)?;

    let queue = DispatchQueue::spawn(AgentBackend::spawn_default(), DEFAULT_QUEUE_CAPACITY);
    let mut attempt = 0_u32;

    loop {
        match connect_once(&url, &config, queue.clone()).await {
            Ok(()) => {
                if !config.reconnect {
                    return Ok(());
                }
                // Reset the backoff counter after a clean session so a brief
                // blip doesn't leave the agent on a long delay forever.
                attempt = 0;
                eprintln!("websocket session closed; reconnecting");
            }
            Err(error) => {
                if !config.reconnect {
                    return Err(error);
                }
                attempt = attempt.saturating_add(1);
                eprintln!("websocket session failed: {error:?}");
            }
        }

        sleep(reconnect_delay(attempt)).await;
    }
}

/// Open one WSS session: send `Hello`, then pump frames until the socket
/// closes or errors. Returns `Ok(())` on a clean close so the caller's reconnect
/// loop can re-enter with a fresh backoff.
async fn connect_once(
    url: &str,
    config: &WebSocketAgentConfig,
    queue: DispatchQueue,
) -> Result<()> {
    let connector = tls_connector(&config.transport)?;
    let (mut socket, response) = connect_async_tls_with_config(url, None, false, Some(connector))
        .await
        .with_context(|| format!("failed to connect to control plane {url}"))?;
    eprintln!(
        "connected to control plane `{url}` with HTTP {}",
        response.status()
    );

    TransportFrame::Hello {
        host_id: config.host_id.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        hostname: hostname(),
        os: env::consts::OS.to_owned(),
        arch: env::consts::ARCH.to_owned(),
    }
    .send(&mut socket)
    .await?;

    while let Some(message) = socket.next().await {
        match message.context("failed to read websocket message")? {
            Message::Text(text) => {
                let frame: TransportFrame =
                    serde_json::from_str(&text).context("invalid websocket frame JSON")?;
                frame.handle(&mut socket, &queue).await?;
            }
            Message::Binary(bytes) => {
                let frame: TransportFrame =
                    serde_json::from_slice(&bytes).context("invalid websocket frame JSON")?;
                frame.handle(&mut socket, &queue).await?;
            }
            // tungstenite handles Ping/Pong at the protocol layer; we just echo.
            Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
            Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(frame) => {
                eprintln!("control plane closed websocket: {frame:?}");
                return Ok(());
            }
        }
    }

    Ok(())
}

fn tls_connector(config: &TransportConfig) -> Result<Connector> {
    let ca_path = config
        .server_ca_path
        .as_deref()
        .context("missing server CA path for outbound WSS")?;
    let cert_path = config
        .client_cert_path
        .as_deref()
        .context("missing client certificate path for outbound WSS")?;
    let key_path = config
        .client_key_path
        .as_deref()
        .context("missing client key path for outbound WSS")?;

    let mut ca_reader = BufReader::new(
        File::open(ca_path).with_context(|| format!("failed to open server CA `{ca_path}`"))?,
    );
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut ca_reader) {
        roots
            .add(certificate.context("failed to parse server CA certificate")?)
            .context("failed to add server CA certificate")?;
    }

    let mut cert_reader = BufReader::new(
        File::open(cert_path)
            .with_context(|| format!("failed to open client certificate `{cert_path}`"))?,
    );
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse client certificate")?;
    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("failed to open client key `{key_path}`"))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse client key")?
        .context("client key PEM contains no private key")?;
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .context("invalid client certificate/private-key pair")?;
    Ok(Connector::Rustls(Arc::new(client)))
}

/// Exponential reconnect backoff with jitter: `2^attempt` seconds, capped at
/// [`MAX_RECONNECT_DELAY`], plus up to 1 second of random jitter to spread out
/// a thundering herd of agents reconnecting after a control-plane restart.
fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(6);
    let base = Duration::from_secs(2_u64.saturating_pow(exponent));
    let capped = base.min(MAX_RECONNECT_DELAY);
    let jitter_ms = rand::rng().random_range(0..=1000);
    capped.saturating_add(Duration::from_millis(jitter_ms))
}

/// Best-effort hostname for the `Hello` frame. `HOSTNAME` is what systemd
/// sets on Linux; `COMPUTERNAME` is the Windows equivalent. We don't fall
/// back to `gethostname()` because the env vars are good enough for a
/// display name and avoid a syscall.
fn hostname() -> Option<String> {
    env::var("HOSTNAME")
        .ok()
        .or_else(|| env::var("COMPUTERNAME").ok())
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn reconnect_delay_is_capped() {
        assert!(reconnect_delay(10) <= MAX_RECONNECT_DELAY + Duration::from_secs(1));
    }

    #[test]
    fn rejects_incomplete_or_plaintext_outbound_tls_configuration() {
        let incomplete = TransportConfig {
            control_plane_url: "wss://dashboard.example.test/tetra".into(),
            ..Default::default()
        };
        (incomplete.validate(&incomplete.control_plane_url)).unwrap_err();

        let plaintext = TransportConfig {
            control_plane_url: "ws://127.0.0.1:7780".into(),
            client_cert_path: Some("client.crt".into()),
            client_key_path: Some("client.key".into()),
            server_ca_path: Some("ca.crt".into()),
        };
        (plaintext.validate(&plaintext.control_plane_url)).unwrap_err();
    }

    #[test]
    fn command_frame_round_trips() {
        let frame = TransportFrame::Command {
            command: AgentCommand {
                id: "cmd-1".into(),
                module: "settings".into(),
                action: "get_system".into(),
                ..Default::default()
            },
        };

        let value: Value = serde_json::from_str(&serde_json::to_string(&frame).unwrap()).unwrap();
        assert_eq!(value["type"], "command");
        assert_eq!(value["command"]["id"], "cmd-1");
    }
}
