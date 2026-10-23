use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context as _, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};

use rand::RngExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, time::sleep};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config, tungstenite::Message,
};

use super::{
    AgentCommand, AgentResponse,
    queue::{DispatchQueue, QueueError},
    transport::TransportConfig,
};
use crate::{
    auth::{
        audit::{self, AuditLog, Origin},
        authz::Principal,
        clock::unix_timestamp,
    },
    enrollment::renewal::{self, ClientFiles, Lifetime},
};

/// Protocol version advertised in the `Hello` frame. Bumped when the wire
/// format changes in a way the control plane must notice; the control plane
/// can refuse or warn on mismatched versions.
const PROTOCOL_VERSION: &str = "2026-10-18";
/// How long to wait for the controller to answer a `Renew` frame before
/// treating the attempt as failed.
const RENEWAL_RESPONSE_TIMEOUT: Duration = Duration::from_mins(5);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
/// Upper bound for reconnect backoff. Without this a long partition could
/// push the delay into hours; capping at 60s keeps the agent responsive to a
/// control-plane restart.
const MAX_RECONNECT_DELAY: Duration = Duration::from_mins(1);
/// How often to ping the control plane, and how long it may stay silent
/// before the session is dropped and redialed.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Upper bound for the TCP, TLS and WebSocket handshakes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Signalled when a network change needs confirmation. `notify_one` keeps a
/// permit, so a change made by a command this session is still dispatching
/// is not missed.
pub static NETWORK_CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Configuration for the outbound WSS control-plane connection (`agent-connect`).
///
/// This is the production transport: the agent dials out to the control plane,
/// authenticates with mTLS, and exchanges [`TransportFrame`]s. Dialing out
/// (rather than listening) keeps the agent behind NAT/firewalls without port
/// forwarding — the same reason a Tailscale tailnet works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketAgentConfig {
    pub transport: TransportConfig,
    pub host_id: String,
    pub reconnect: bool,
}

/// The wire frame for the WSS control-plane protocol. Tagged with `type` so a
/// single `serde_json` parse dispatches on the frame kind.
///
/// The agent side only ever sends `Hello`, `Response`, `Pong`, `Error` and
/// `Renew`; it receives `Command`, `Ping`, `Renewed` and `RenewFailed`. The
/// other variants appear in this enum
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
    /// Ask the controller to sign a CSR for a fresh key (client certificate
    /// renewal).
    Renew {
        csr: String,
    },
    /// The controller's answer to `Renew`: the signed certificate, leaf first.
    Renewed {
        client_certificate: String,
    },
    /// The controller refused or could not process `Renew`.
    RenewFailed {
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

    /// Dispatch one received frame. `Command` frames are authorized as the
    /// remote controller, go to the backend actor, are recorded in the action
    /// log as remote actions, and the response is sent back as a `Response`
    /// frame; `Ping` is echoed as a `Pong`; anything else (including `Hello`,
    /// `Response`, `Pong`, `Error`) is rejected with an `Error` frame — the
    /// control plane should never send those to an agent.
    async fn handle<S>(self, socket: &mut S, queue: &DispatchQueue, remote: &Remote) -> Result<()>
    where
        S: SinkExt<Message> + Unpin,
        <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
    {
        match self {
            Self::Command { command }
                if !Principal::RemoteController.allows(&command.module, &command.action) =>
            {
                Self::Error {
                    error: format!("{}.{} is not allowed", command.module, command.action),
                }
                .send(socket)
                .await?;
            }
            Self::Command { mut command } => {
                // `user` is for transports that authenticated a host user;
                // the controller cannot pick one (or put it in the log).
                command.user = None;
                // The action log only needs the envelope; don't deep-copy a
                // (possibly multi-megabyte) payload for it.
                let payload = std::mem::take(&mut command.payload);
                let logged = command.clone();
                command.payload = payload;
                match dispatch_with_keepalive(socket, queue, command).await? {
                    Ok(response) => {
                        remote.record(&logged, &response);
                        Self::Response { response }.send(socket).await?;
                    }
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
                }
            }
            Self::Ping { id, sent_at } => {
                Self::Pong { id, sent_at }.send(socket).await?;
            }
            Self::Hello { .. }
            | Self::Response { .. }
            | Self::Pong { .. }
            | Self::Error { .. }
            | Self::Renew { .. }
            | Self::Renewed { .. }
            | Self::RenewFailed { .. } => {
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

/// Who is sending commands on an outbound session, for authorization and the
/// action log.
struct Remote {
    host_id: String,
    audit: AuditLog,
}

impl Remote {
    fn record(&self, command: &AgentCommand, response: &AgentResponse) {
        self.audit.record(&audit::Entry {
            at: unix_timestamp(),
            origin: Origin::Remote,
            client: None,
            uid: None,
            username: command.user.clone(),
            host_id: Some(self.host_id.clone()),
            command_id: command.id.clone(),
            module: command.module.clone(),
            action: command.action.clone(),
            ok: response.ok,
            error: response.error.clone(),
        });
    }
}

/// Connect to the control plane and run sessions until one closes for good.
///
/// Reconnects with backoff when `reconnect` is set. Uses an existing dispatch queue,
/// so the outbound session shares one dispatcher with the local transports,
/// and records remote actions in `audit`.
///
/// The outer loop is the reconnect loop; the inner [`connect_once`] is a single
/// session.
pub async fn run_with_queue(
    config: WebSocketAgentConfig,
    queue: DispatchQueue,
    audit: AuditLog,
) -> Result<()> {
    let url = config.transport.wss_url()?.to_owned();

    let mut attempt = 0_u32;
    let mut renewal = RenewalState::default();

    loop {
        match connect_once(&url, &config, queue.clone(), &audit, &mut renewal).await {
            // Reconnect straight away with the renewed certificate, whether
            // or not `reconnect` is set: the session only ended to swap it.
            Ok(SessionEnd::Renewed) => {
                attempt = 0;
                eprintln!("reconnecting with the renewed client certificate");
                continue;
            }
            Ok(SessionEnd::NetworkChanged) => {
                attempt = 0;
                eprintln!("network change awaits confirmation; reconnecting");
                continue;
            }
            Ok(SessionEnd::Closed) => {
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

/// Why a session ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnd {
    /// The control plane closed the connection.
    Closed,
    /// A network change awaits confirmation and has likely cut this
    /// connection; redial now rather than after the idle timeout, so the
    /// controller can confirm (`network.pending`, `network.confirm`) before
    /// the change rolls back.
    NetworkChanged,
    /// A renewed certificate was staged; reconnect with it.
    Renewed,
}

/// Renewal state that outlives one session.
#[derive(Debug, Default)]
struct RenewalState {
    /// No renewal is attempted before this time. Set when an attempt starts,
    /// so a failed or interrupted attempt is not retried on every reconnect,
    /// and cleared once a renewed certificate is in use.
    retry_at: Option<SystemTime>,
}

/// Open one WSS session: send `Hello`, then pump frames until the socket
/// closes or errors, renewing the client certificate when it is due. Returns
/// `Ok` on a clean close so the caller's reconnect loop can re-enter with a
/// fresh backoff.
async fn connect_once(
    url: &str,
    config: &WebSocketAgentConfig,
    queue: DispatchQueue,
    audit: &AuditLog,
    renewal: &mut RenewalState,
) -> Result<SessionEnd> {
    let files = ClientFiles::from_transport(&config.transport);
    let mut socket = open(url, &config.transport, files.as_ref(), renewal).await?;

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

    let mut session = Session {
        renewer: files.and_then(|files| Renewer::new(files, &config.host_id)),
        queue,
        remote: Remote {
            host_id: config.host_id.clone(),
            audit: audit.clone(),
        },
    };
    // Without traffic a NAT drop or a silently dead controller would leave
    // `socket.next()` waiting forever; ping, and reconnect after silence.
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seen = tokio::time::Instant::now();
    loop {
        let wake = session
            .renewer
            .as_ref()
            .map(|renewer| renewer.wake_at(renewal));
        let event = tokio::select! {
            message = socket.next() => message,
            () = sleep_until(wake) => {
                if let Some(renewer) = &mut session.renewer {
                    renewer.on_timer(&mut socket, renewal).await?;
                }
                continue;
            }
            () = NETWORK_CHANGED.notified() => return Ok(SessionEnd::NetworkChanged),
            _ = keepalive.tick() => {
                ensure!(
                    last_seen.elapsed() < IDLE_TIMEOUT,
                    "control plane silent for {IDLE_TIMEOUT:?}"
                );
                socket.send(Message::Ping(Vec::new().into())).await?;
                continue;
            }
        };
        let Some(message) = event else {
            return Ok(SessionEnd::Closed);
        };
        let end = session.on_message(&mut socket, message).await?;
        // After handling too: commands are dispatched inline.
        last_seen = tokio::time::Instant::now();
        if let Some(end) = end {
            return Ok(end);
        }
    }
}

/// Dial the control plane, trying a staged renewed certificate first.
///
/// The staged pair replaces the current one only once the controller accepts
/// it. If it is refused but the current pair still works, the staged pair is
/// discarded. If neither connects, the staged pair is kept for the next
/// attempt, since the controller may just be unreachable.
async fn open(
    url: &str,
    transport: &TransportConfig,
    files: Option<&ClientFiles>,
    renewal: &mut RenewalState,
) -> Result<Socket> {
    let Some(files) = files else {
        return dial(url, transport).await;
    };
    files.recover()?;
    if !files.is_staged() {
        return dial(url, transport).await;
    }
    match dial(url, &files.staged_transport(transport)).await {
        Ok(socket) => {
            files.promote()?;
            renewal.retry_at = None;
            eprintln!("renewed client certificate accepted; replaced the old certificate");
            Ok(socket)
        }
        Err(error) => {
            eprintln!(
                "renewed client certificate did not work: {error:?}; trying the current certificate"
            );
            let socket = dial(url, transport).await?;
            files.discard()?;
            eprintln!("discarded the renewed client certificate; keeping the current one");
            Ok(socket)
        }
    }
}

async fn dial(url: &str, transport: &TransportConfig) -> Result<Socket> {
    let connector = tls_connector(transport)?;
    let (socket, response) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_async_tls_with_config(url, None, false, Some(connector)),
    )
    .await
    .with_context(|| format!("timed out connecting to control plane {url}"))?
    .with_context(|| format!("failed to connect to control plane {url}"))?;
    eprintln!(
        "connected to control plane `{url}` with HTTP {}",
        response.status()
    );
    Ok(socket)
}

/// Dispatch `command`, pinging the controller while it runs: a command can
/// take minutes (an image pull on start), and idle timeouts on the controller
/// or a proxy must not drop the session before the response.
async fn dispatch_with_keepalive<S>(
    socket: &mut S,
    queue: &DispatchQueue,
    command: AgentCommand,
) -> Result<Result<AgentResponse, QueueError>>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
{
    let mut dispatch = std::pin::pin!(queue.dispatch(command));
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    // The first tick would fire at once.
    keepalive.reset();
    loop {
        tokio::select! {
            result = &mut dispatch => return Ok(result),
            _ = keepalive.tick() => socket.send(Message::Ping(Vec::new().into())).await?,
        }
    }
}

/// Sleep until `wake`, or forever when it is `None`.
async fn sleep_until(wake: Option<SystemTime>) {
    match wake {
        Some(wake) => sleep(wake.duration_since(SystemTime::now()).unwrap_or_default()).await,
        None => std::future::pending().await,
    }
}

/// One established session.
struct Session {
    renewer: Option<Renewer>,
    queue: DispatchQueue,
    /// Records the controller's actions in the action log.
    remote: Remote,
}

impl Session {
    /// Handle one message. Returns `Some` when the session should end.
    async fn on_message(
        &mut self,
        socket: &mut Socket,
        message: Result<Message, tokio_tungstenite::tungstenite::Error>,
    ) -> Result<Option<SessionEnd>> {
        let frame: TransportFrame = match message.context("failed to read websocket message")? {
            Message::Text(text) => {
                serde_json::from_str(&text).context("invalid websocket frame JSON")?
            }
            Message::Binary(bytes) => {
                serde_json::from_slice(&bytes).context("invalid websocket frame JSON")?
            }
            // tungstenite answers pings itself.
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => return Ok(None),
            Message::Close(frame) => {
                eprintln!("control plane closed websocket: {frame:?}");
                return Ok(Some(SessionEnd::Closed));
            }
        };
        match (frame, &mut self.renewer) {
            (TransportFrame::Renewed { client_certificate }, Some(renewer)) => {
                if !renewer.on_renewed(&client_certificate) {
                    return Ok(None);
                }
                if let Err(error) = socket.close(None).await {
                    eprintln!("failed to close the session cleanly: {error}");
                }
                Ok(Some(SessionEnd::Renewed))
            }
            (TransportFrame::RenewFailed { error }, Some(renewer)) => {
                renewer.on_failed(&error);
                Ok(None)
            }
            (frame, _) => {
                frame.handle(socket, &self.queue, &self.remote).await?;
                Ok(None)
            }
        }
    }
}

/// Client certificate renewal for one session.
struct Renewer {
    files: ClientFiles,
    lifetime: Lifetime,
    common_name: String,
    /// The request sent to the controller, and when to give up on it.
    pending: Option<(renewal::Request, SystemTime)>,
}

impl Renewer {
    /// Renewal for the certificate in `files`, or `None` (logged) when it
    /// cannot be read.
    fn new(files: ClientFiles, common_name: &str) -> Option<Self> {
        let lifetime = Lifetime::read(&files.certificate)
            .inspect_err(|error| {
                eprintln!("{error:#}; client certificate renewal disabled for this session");
            })
            .ok()?;
        Some(Self {
            files,
            lifetime,
            common_name: common_name.to_owned(),
            pending: None,
        })
    }

    /// When the timer should next fire: the pending request's deadline, or
    /// when renewal is due (and not held back by a recent failure).
    fn wake_at(&self, state: &RenewalState) -> SystemTime {
        if let Some((_, deadline)) = &self.pending {
            return *deadline;
        }
        let due = self.lifetime.renew_at();
        state.retry_at.map_or(due, |retry_at| due.max(retry_at))
    }

    async fn on_timer(&mut self, socket: &mut Socket, state: &mut RenewalState) -> Result<()> {
        if self.pending.take().is_some() {
            eprintln!("the control plane did not answer the certificate renewal request");
            return Ok(());
        }
        let now = SystemTime::now();
        state.retry_at = now.checked_add(self.lifetime.retry_delay(now));
        let request = match renewal::Request::new(&self.common_name) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("failed to start client certificate renewal: {error:#}");
                return Ok(());
            }
        };
        eprintln!("client certificate renewal is due; sending a new CSR to the control plane");
        TransportFrame::Renew {
            csr: request.csr.clone(),
        }
        .send(socket)
        .await?;
        let deadline = now
            .checked_add(RENEWAL_RESPONSE_TIMEOUT)
            .context("renewal deadline is outside the supported time range")?;
        self.pending = Some((request, deadline));
        Ok(())
    }

    /// Stage the renewed certificate. Returns whether the session should end
    /// so the agent reconnects with it.
    fn on_renewed(&mut self, certificate: &str) -> bool {
        let Some((request, _)) = self.pending.take() else {
            eprintln!("ignoring a renewed certificate that was not requested");
            return false;
        };
        match request.stage(&self.files, certificate) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("client certificate renewal failed: {error:#}; keeping the current one");
                false
            }
        }
    }

    fn on_failed(&mut self, error: &str) {
        if self.pending.take().is_some() {
            eprintln!(
                "the control plane refused to renew the client certificate: {error}; keeping the current one"
            );
        } else {
            eprintln!("ignoring an unexpected renew_failed frame: {error}");
        }
    }
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

    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(ca_path)
        .with_context(|| format!("failed to open server CA `{ca_path}`"))?
    {
        roots
            .add(certificate.context("failed to parse server CA certificate")?)
            .context("failed to add server CA certificate")?;
    }
    ensure!(
        !roots.is_empty(),
        "server CA `{ca_path}` contains no certificates"
    );

    let certificates = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to open client certificate `{cert_path}`"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse client certificate")?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to read client key `{key_path}`"))?;
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

/// Best-effort kernel hostname. systemd does not set `HOSTNAME` for
/// services (it is a shell variable), so read it from procfs first.
pub(crate) fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| env::var("HOSTNAME").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn reconnect_delay_is_capped() {
        assert!(reconnect_delay(10) <= MAX_RECONNECT_DELAY + Duration::from_secs(1));
    }

    #[tokio::test]
    async fn remote_commands_are_recorded_as_remote_actions() {
        let dir = tempfile::tempdir().unwrap();
        let remote = Remote {
            host_id: "host-01".into(),
            audit: AuditLog::new(dir.path().to_path_buf()),
        };
        let queue = DispatchQueue::spawn(
            crate::agent::Dispatcher::full(),
            crate::agent::queue::DEFAULT_QUEUE_CAPACITY,
        );
        let frame = TransportFrame::Command {
            command: AgentCommand {
                id: "cmd-remote".into(),
                module: "settings".into(),
                action: "get_system".into(),
                ..Default::default()
            },
        };
        frame
            .handle(&mut futures_util::sink::drain(), &queue, &remote)
            .await
            .unwrap();
        let logged = remote.audit.recent(10, Some(Origin::Remote)).unwrap();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].command_id, "cmd-remote");
        assert_eq!(logged[0].host_id.as_deref(), Some("host-01"));
        assert!(logged[0].ok);
    }

    #[test]
    fn renewal_frames_round_trip() {
        let value = serde_json::to_value(TransportFrame::Renew { csr: "csr".into() }).unwrap();
        assert_eq!(value, serde_json::json!({ "type": "renew", "csr": "csr" }));

        let frame: TransportFrame = serde_json::from_value(
            serde_json::json!({ "type": "renewed", "client_certificate": "pem" }),
        )
        .unwrap();
        assert!(matches!(
            frame,
            TransportFrame::Renewed { client_certificate } if client_certificate == "pem"
        ));
        let frame: TransportFrame =
            serde_json::from_value(serde_json::json!({ "type": "renew_failed", "error": "no" }))
                .unwrap();
        assert!(matches!(frame, TransportFrame::RenewFailed { error } if error == "no"));
    }

    #[test]
    fn renewal_waits_for_a_failed_attempt_to_cool_down() {
        let root = tempfile::tempdir().unwrap();
        let certificate = root.path().join("client.crt");
        let key = rcgen::KeyPair::generate().unwrap();
        std::fs::write(
            &certificate,
            rcgen::CertificateParams::default()
                .self_signed(&key)
                .unwrap()
                .pem(),
        )
        .unwrap();
        let renewer = Renewer::new(
            ClientFiles {
                certificate,
                key: root.path().join("client.key"),
            },
            "host-01",
        )
        .unwrap();
        let due = renewer.lifetime.renew_at();

        let mut state = RenewalState::default();
        assert_eq!(renewer.wake_at(&state), due);
        let later = due.checked_add(Duration::from_secs(60)).unwrap();
        state.retry_at = Some(later);
        assert_eq!(renewer.wake_at(&state), later);
        state.retry_at = due.checked_sub(Duration::from_secs(60));
        assert_eq!(renewer.wake_at(&state), due);
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
