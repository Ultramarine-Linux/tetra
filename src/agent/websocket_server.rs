//! Development inbound WebSocket server for dashboard-to-Tetra connections.
//!
//! This is intentionally separate from `websocket.rs`, which is the outbound
//! production control-plane transport. The server requires an explicitly
//! configured controller public key and authenticates before dispatching frames.

use std::{
    collections::BTreeMap,
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use kameo::actor::Spawn;
use rand::RngExt;
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{accept_async, tungstenite::Message};

use super::{
    AgentBackend,
    crypto::{parse_verifying_key, public_key_fingerprint, verify_challenge_signature},
    identity::HostIdentity,
    protocol::{AuthFrame, AuthenticatedSession, PROTOCOL_VERSION, SessionPolicy, unix_timestamp},
    queue::{DEFAULT_QUEUE_CAPACITY, DispatchQueue, QueueError},
    verify_password::verify_password,
};
use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone)]
pub struct WebSocketServerConfig {
    pub listen: SocketAddr,
    /// Explicit controller key for development. Once enrolled, the persisted
    /// key under `identity_dir` is used on subsequent starts.
    pub controller_public_key: Option<String>,
    /// One-time token accepted only while no controller key is enrolled.
    pub enrollment_token: Option<String>,
    pub identity_dir: PathBuf,
    /// Paths to TLS certificate and key
    pub tls_cert_key_path: Option<(PathBuf, PathBuf)>,
}
impl WebSocketServerConfig {
    fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        Ok((self.tls_cert_key_path.as_ref())
            .map(Self::load_tls_config)
            .transpose()?
            .map(Arc::new)
            .map(TlsAcceptor::from))
    }

    fn load_tls_config((cert_path, key_path): &(PathBuf, PathBuf)) -> Result<rustls::ServerConfig> {
        let mut cert_reader = BufReader::new(File::open(cert_path).with_context(|| {
            format!("failed to open TLS certificate `{}`", cert_path.display())
        })?);
        let certificates = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse TLS certificate PEM")?;
        let mut key_reader = BufReader::new(
            File::open(key_path)
                .with_context(|| format!("failed to open TLS key `{}`", key_path.display()))?,
        );
        let key = rustls_pemfile::private_key(&mut key_reader)
            .context("failed to parse TLS private key PEM")?
            .ok_or_else(|| anyhow::anyhow!("TLS private key PEM contains no private key"))?;
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .context("invalid TLS certificate/private-key pair")
    }

    pub async fn serve(self) -> Result<()> {
        let tls_acceptor = self.tls_acceptor()?;
        validate_listener_security(&self.listen, tls_acceptor.is_some())?;

        let identity = HostIdentity::load_or_generate(&self.identity_dir)?;
        let persisted_controller_key = identity.load_controller_key()?;
        let controller_public_key =self.controller_public_key.map(|configured| {
            if let Some(persisted) = &persisted_controller_key {
                ensure!(
                    persisted == &configured,
                    "configured controller key differs from the enrolled key; rotate it explicitly"
                );
            } else {
                // `--controller-public-key` is a bootstrap convenience. Keep
                // it in the mutable identity store so the agent does not become
                // unpaired on its next restart.
                identity.enroll_controller_key(&configured)?;
            }
            Ok(configured)
        }).transpose()?.or(persisted_controller_key)
        .map(|key| parse_verifying_key(&key).context("invalid controller public key"))
        .transpose()?;
        let listener = TcpListener::bind(self.listen).await.with_context(|| {
            format!(
                "failed to bind development WebSocket listener on {}",
                self.listen
            )
        })?;
        let dispatcher = crate::agent::Dispatcher::full();
        let privileged_actions = build_privilege_map(&dispatcher);
        let queue = DispatchQueue::spawn(AgentBackend::spawn(dispatcher), DEFAULT_QUEUE_CAPACITY);

        eprintln!(
            "serving authenticated Tetra WebSocket on {}://{}",
            if tls_acceptor.is_some() { "wss" } else { "ws" },
            self.listen
        );
        eprintln!("host identity: {}", identity.path().display());
        eprintln!(
            "host fingerprint: {}",
            public_key_fingerprint(&identity.verifying_key())
        );

        loop {
            let (stream, peer) = listener.accept().await?;
            let queue = queue.clone();
            let identity = identity.clone();
            let enrollment_token = self.enrollment_token.clone();
            let tls_acceptor = tls_acceptor.clone();
            let privileged_actions = privileged_actions.clone();
            tokio::spawn(async move {
                let stream = match tls_acceptor {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(stream) => Box::new(stream) as Box<dyn AsyncReadWrite>,
                        Err(error) => {
                            eprintln!("TLS peer {peer} failed handshake: {error}");
                            return;
                        }
                    },
                    None => Box::new(stream) as Box<dyn AsyncReadWrite>,
                };
                if let Err(error) = handle_connection(ConnectionHandler {
                    stream,
                    peer,
                    queue,
                    identity,
                    controller_key: controller_public_key,
                    enrollment_token,
                    privileged_actions: privileged_actions.clone(),
                })
                .await
                {
                    eprintln!("WebSocket peer {peer} closed with error: {error:?}");
                }
            });
        }
    }
}

struct ConnectionHandler {
    stream: Box<dyn AsyncReadWrite>,
    peer: SocketAddr,
    queue: DispatchQueue,
    identity: HostIdentity,
    controller_key: Option<VerifyingKey>,
    enrollment_token: Option<String>,
    privileged_actions: BTreeMap<String, Vec<String>>,
}

type WebSocket = tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>;

struct AuthenticatedConnection {
    socket: WebSocket,
    peer: SocketAddr,
    queue: DispatchQueue,
    session: AuthenticatedSession,
    privileged_actions: BTreeMap<String, Vec<String>>,
}

async fn establish_connection(
    ConnectionHandler {
        stream,
        peer,
        queue,
        identity,
        controller_key,
        enrollment_token,
        privileged_actions,
    }: ConnectionHandler,
) -> Result<AuthenticatedConnection> {
    let mut socket = accept_async(stream)
        .await
        .context("WebSocket handshake failed")?;
    // Enrollment updates the identity store while the server is running. Reload
    // the persisted key per connection instead of relying only on the startup
    // snapshot, so the next Dashboard request can authenticate immediately.
    let controller_key = if let Some(key) = controller_key {
        key
    } else if let Some(key) = identity.load_controller_key()? {
        parse_verifying_key(&key).context("invalid persisted controller public key")?
    } else {
        request_enroll_pubkey(&identity, enrollment_token, &mut socket).await?
    };
    let session = auth(
        identity,
        &mut socket,
        random_token(24),
        random_token(32),
        controller_key,
    )
    .await?;

    Ok(AuthenticatedConnection {
        socket,
        peer,
        queue,
        session,
        privileged_actions,
    })
}

#[allow(clippy::too_many_lines)]
async fn handle_connection(connection: ConnectionHandler) -> Result<()> {
    const ELEVATION_TTL: Duration = Duration::from_mins(30);

    let AuthenticatedConnection {
        mut socket,
        peer,
        queue,
        mut session,
        privileged_actions,
    } = establish_connection(connection).await?;

    // Elevation grant for headless servers. The dashboard provides the
    // administrator password via PasswordResponse.
    let mut elevation: Option<HeadlessElevationGrant> = None;
    let mut pending_prompt: Option<String> = None;

    while let Some(message) = socket.next().await {
        let frame = parse_message(message?)?;
        match frame {
            AuthFrame::ElevationRequest {
                session_id: requested_session,
            } => {
                if requested_session != session.session_id() {
                    send_error(&mut socket, "elevation request session does not match").await?;
                    continue;
                }
                let prompt_id = random_token(24);
                pending_prompt = Some(prompt_id.clone());
                send(
                    &mut socket,
                    &AuthFrame::PasswordPrompt {
                        prompt_id,
                        action_id: "io.tetra.agent.elevate".into(),
                        message: "Enter the server administrator password to enable privileged operations.".into(),
                        expires_at: unix_timestamp().saturating_add(300),
                    },
                )
                .await?;
            }
            AuthFrame::PasswordResponse {
                prompt_id,
                response: password,
            } => {
                let Some(expected) = &pending_prompt else {
                    send_error(&mut socket, "no pending prompt for response").await?;
                    continue;
                };
                if &prompt_id != expected {
                    send_error(&mut socket, "prompt id does not match pending prompt").await?;
                    continue;
                }
                pending_prompt = None;
                // Verify the password against the host account selected during
                // authentication. Dashboard supplies this from its explicit
                // Dashboard-user to host-user mapping; never silently fall back
                // to root for a per-user elevation request.
                let Some(username) = session.user().map(str::to_owned) else {
                    send(
                        &mut socket,
                        &AuthFrame::ElevationStatus {
                            state: super::protocol::ElevationState::Unavailable,
                            expires_at: None,
                            message: Some(
                                "A mapped host user is required before elevation.".into(),
                            ),
                        },
                    )
                    .await?;
                    continue;
                };
                match verify_password(&username, &password) {
                    Ok(true) => {
                        let grant = HeadlessElevationGrant::new(ELEVATION_TTL);
                        let expires_at = grant
                            .expires_in_seconds()
                            .map(|s| unix_timestamp().saturating_add(s));
                        elevation = Some(grant);
                        send(
                            &mut socket,
                            &AuthFrame::ElevationStatus {
                                state: super::protocol::ElevationState::Active,
                                expires_at,
                                message: Some(
                                    "Administrator mode is active. Privileged operations may now proceed."
                                        .into(),
                                ),
                            },
                        )
                        .await?;
                    }
                    Ok(false) => {
                        send(
                            &mut socket,
                            &AuthFrame::ElevationStatus {
                                state: super::protocol::ElevationState::Inactive,
                                expires_at: None,
                                message: Some("Incorrect password.".into()),
                            },
                        )
                        .await?;
                    }
                    Err(error) => {
                        send(
                            &mut socket,
                            &AuthFrame::ElevationStatus {
                                state: super::protocol::ElevationState::Inactive,
                                expires_at: None,
                                message: Some(format!("Password verification failed: {error}")),
                            },
                        )
                        .await?;
                    }
                }
            }
            AuthFrame::PasswordCancel { prompt_id } => {
                if pending_prompt.as_ref() == Some(&prompt_id) {
                    pending_prompt = None;
                }
                send(
                    &mut socket,
                    &AuthFrame::ElevationStatus {
                        state: super::protocol::ElevationState::Inactive,
                        expires_at: None,
                        message: Some("Elevation prompt was cancelled.".into()),
                    },
                )
                .await?;
            }
            AuthFrame::ElevationRevoke {
                session_id: requested_session,
            } => {
                if requested_session != session.session_id() {
                    send_error(&mut socket, "elevation revoke session does not match").await?;
                    continue;
                }
                elevation = None;
                send(
                    &mut socket,
                    &AuthFrame::ElevationStatus {
                        state: super::protocol::ElevationState::Inactive,
                        expires_at: None,
                        message: Some("Administrator mode was revoked.".into()),
                    },
                )
                .await?;
            }
            AuthFrame::Command { .. } => {
                let now = unix_timestamp();
                let mut command = session.accept_command(&frame, now)?.clone();
                command.user = session.user().map(std::borrow::ToOwned::to_owned);

                // Reject privileged actions when there is no active elevation grant.
                if let Some(actions) = privileged_actions.get(&command.module)
                    && actions.contains(&command.action)
                {
                    match &elevation {
                        Some(grant) if grant.is_active() => {}
                        _ => {
                            send_error(
                                &mut socket,
                                "privileged action requires elevation; request elevation first",
                            )
                            .await?;
                            continue;
                        }
                    }
                }

                if let Some(grant) = &elevation
                    && !grant.is_active()
                {
                    elevation = None;
                    send(&mut socket, &AuthFrame::ElevationStatus {
                        state: super::protocol::ElevationState::Inactive,
                        expires_at: None,
                        message: Some("Administrator mode expired; request elevation again before a privileged operation.".into()),
                    }).await?;
                }

                match queue.dispatch(command).await {
                    Ok(response) => send(&mut socket, &AuthFrame::Response { response }).await?,
                    Err(QueueError::Full) => {
                        send_error(
                            &mut socket,
                            "Tetra command queue is full; retry after backoff",
                        )
                        .await?;
                    }
                    Err(QueueError::Closed) => {
                        send_error(&mut socket, "Tetra command queue is unavailable").await?;
                        bail!("dispatch queue closed")
                    }
                }
            }
            AuthFrame::Error { error } => bail!("peer reported error: {error}"),
            _ => {
                send_error(&mut socket, "unsupported frame after authentication").await?;
                bail!("unsupported authenticated frame from {peer}")
            }
        }
    }
    Ok(())
}

async fn auth(
    identity: HostIdentity,
    socket: &mut tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>,
    session_id: String,
    challenge: String,
    controller_key: VerifyingKey,
) -> Result<AuthenticatedSession, anyhow::Error> {
    send(
        socket,
        &AuthFrame::Challenge {
            protocol_version: PROTOCOL_VERSION.into(),
            session_id: session_id.clone(),
            challenge: challenge.clone(),
            host_fingerprint: public_key_fingerprint(&identity.verifying_key()),
        },
    )
    .await?;
    let Some(message) = socket.next().await else {
        bail!("peer disconnected before authentication")
    };
    let AuthFrame::Authenticate {
        protocol_version,
        session_id: received_session,
        public_key,
        signature,
        user,
    } = parse_message(message?)?
    else {
        send_error(socket, "authentication is required before commands").await?;
        bail!("peer sent non-authentication frame")
    };
    if protocol_version != PROTOCOL_VERSION || received_session != session_id {
        send_error(socket, "protocol version or session id mismatch").await?;
        bail!("authentication context mismatch")
    }
    let supplied_key = parse_verifying_key(&public_key)?;
    if supplied_key != controller_key {
        send_error(socket, "controller public key is not enrolled").await?;
        bail!("controller public key is not enrolled")
    }
    verify_challenge_signature(
        &controller_key,
        &signature,
        &protocol_version,
        &session_id,
        &challenge,
    )?;
    let session = AuthenticatedSession::new(
        session_id.clone(),
        controller_key,
        user.clone(),
        SessionPolicy::default(),
    )?;
    send(
        socket,
        &AuthFrame::Response {
            response: super::AgentResponse::ok("authenticated", json!({"session_id": session_id})),
        },
    )
    .await?;
    Ok(session)
}

async fn request_enroll_pubkey(
    identity: &HostIdentity,
    enrollment_token: Option<String>,
    socket: &mut tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>,
) -> Result<VerifyingKey, anyhow::Error> {
    send(
        socket,
        &AuthFrame::EnrollmentRequired {
            host_fingerprint: public_key_fingerprint(&identity.verifying_key()),
        },
    )
    .await?;
    let Some(message) = socket.next().await else {
        bail!("peer disconnected before enrollment")
    };
    let AuthFrame::Enroll { token, public_key } = parse_message(message?)? else {
        send_error(socket, "controller enrollment is required").await?;
        bail!("peer sent non-enrollment frame to unpaired host")
    };
    let expected_token = enrollment_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no enrollment token configured"))?;
    if token != expected_token {
        send_error(socket, "invalid enrollment token").await?;
        bail!("invalid enrollment token")
    }
    let key = parse_verifying_key(&public_key).context("invalid enrollment public key")?;
    identity.enroll_controller_key(&public_key)?;
    send(
        socket,
        &AuthFrame::Response {
            response: super::AgentResponse::ok(
                "enrolled",
                json!({"host_fingerprint": public_key_fingerprint(&identity.verifying_key())}),
            ),
        },
    )
    .await?;
    Ok(key)
}

fn parse_message(message: Message) -> Result<AuthFrame> {
    match message {
        Message::Text(text) => {
            serde_json::from_str(&text).context("invalid authenticated WebSocket JSON")
        }
        Message::Binary(bytes) => {
            serde_json::from_slice(&bytes).context("invalid authenticated WebSocket JSON")
        }
        Message::Close(_) => bail!("peer closed WebSocket"),
        Message::Ping(_) | Message::Pong(_) => bail!("unexpected WebSocket control frame"),
        Message::Frame(_) => bail!("unexpected raw WebSocket frame"),
    }
}

async fn send<S>(socket: &mut S, frame: &AuthFrame) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
{
    let text = serde_json::to_string(frame)?;
    socket
        .send(Message::Text(text.into()))
        .await
        .context("failed to send authenticated frame")
}

async fn send_error<S>(socket: &mut S, error: &str) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
{
    send(
        socket,
        &AuthFrame::Error {
            error: error.into(),
        },
    )
    .await
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

#[inline]
fn validate_listener_security(listen: &SocketAddr, tls_enabled: bool) -> Result<()> {
    ensure!(
        listen.ip().is_loopback() || tls_enabled,
        "non-loopback WebSocket listeners require --tls-cert and --tls-key"
    );
    Ok(())
}

/// In-memory elevation grant for headless hosts. Verified against a password
/// provided by the dashboard.
#[derive(Debug, Clone)]
struct HeadlessElevationGrant {
    expires_at: Instant,
}

impl HeadlessElevationGrant {
    fn new(ttl: Duration) -> Self {
        Self {
            #[allow(clippy::arithmetic_side_effects)]
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_active(&self) -> bool {
        Instant::now() < self.expires_at
    }

    fn expires_in_seconds(&self) -> Option<i64> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .and_then(|d| i64::try_from(d.as_secs()).ok())
    }
}

fn build_privilege_map(dispatcher: &super::Dispatcher) -> BTreeMap<String, Vec<String>> {
    dispatcher
        .capabilities()
        .into_iter()
        .map(|info| {
            (
                info.name.to_owned(),
                info.privileged_actions
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn random_token(len: usize) -> String {
    let mut value = vec![0_u8; len];
    rand::rng().fill(&mut value[..]);
    URL_SAFE_NO_PAD.encode(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        AgentCommand,
        crypto::{public_key_fingerprint, sign_challenge, sign_command},
    };
    use ed25519_dalek::SigningKey;
    use futures_util::{SinkExt, StreamExt};
    use tempfile::tempdir;
    use tokio::net::TcpStream;
    use tokio_tungstenite::connect_async;

    async fn receive(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<TcpStream>,
        >,
    ) -> AuthFrame {
        let message = socket.next().await.unwrap().unwrap();
        parse_message(message).unwrap()
    }

    #[test]
    fn random_tokens_are_non_empty_and_different() {
        let first = random_token(16);
        let second = random_token(16);
        assert_ne!(first, "");
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_non_loopback_plaintext_listener() {
        let address: SocketAddr = "192.0.2.1:7780".parse().unwrap();
        assert!(validate_listener_security(&address, false).is_err());
    }

    #[tokio::test]
    async fn enrollment_persists_controller_key_and_continues_to_challenge() {
        let controller = SigningKey::from_bytes(&[13_u8; 32]);
        let identity_dir = tempdir().unwrap();
        let identity = HostIdentity::load_or_generate(identity_dir.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let queue = DispatchQueue::spawn(AgentBackend::spawn_default(), DEFAULT_QUEUE_CAPACITY);
        let expected_host_fingerprint = public_key_fingerprint(&identity.verifying_key());
        let controller_public_key = public_key_fingerprint(&controller.verifying_key());

        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(ConnectionHandler {
                stream: Box::new(stream),
                peer,
                queue,
                identity,
                controller_key: None,
                enrollment_token: Some("enroll-once".into()),
                privileged_actions: BTreeMap::new(),
            })
            .await
            .unwrap();
        });

        let (mut socket, _) = connect_async(format!("ws://{address}")).await.unwrap();
        let required = receive(&mut socket).await;
        assert!(
            matches!(required, AuthFrame::EnrollmentRequired { host_fingerprint } if host_fingerprint == expected_host_fingerprint)
        );
        let enroll = AuthFrame::Enroll {
            token: "enroll-once".into(),
            public_key: controller_public_key.clone(),
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&enroll).unwrap().into(),
            ))
            .await
            .unwrap();
        assert!(
            matches!(receive(&mut socket).await, AuthFrame::Response { response } if response.ok)
        );
        let AuthFrame::Challenge {
            protocol_version,
            session_id,
            challenge,
            ..
        } = receive(&mut socket).await
        else {
            panic!("expected post-enrollment challenge")
        };
        let authenticate = AuthFrame::Authenticate {
            protocol_version: protocol_version.clone(),
            session_id: session_id.clone(),
            public_key: controller_public_key,
            signature: sign_challenge(&controller, &protocol_version, &session_id, &challenge),
            user: None,
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&authenticate).unwrap().into(),
            ))
            .await
            .unwrap();
        assert!(
            matches!(receive(&mut socket).await, AuthFrame::Response { response } if response.ok)
        );
        socket.close(None).await.unwrap();

        assert_eq!(
            HostIdentity::load_or_generate(identity_dir.path())
                .unwrap()
                .load_controller_key()
                .unwrap(),
            Some(public_key_fingerprint(&controller.verifying_key()))
        );
    }

    #[tokio::test]
    async fn authenticated_client_can_dispatch_a_command() {
        let controller = SigningKey::from_bytes(&[11_u8; 32]);
        let identity_dir = tempdir().unwrap();
        let identity = HostIdentity::load_or_generate(identity_dir.path()).unwrap();
        let expected_host_fingerprint = public_key_fingerprint(&identity.verifying_key());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let queue = DispatchQueue::spawn(AgentBackend::spawn_default(), DEFAULT_QUEUE_CAPACITY);
        let controller_key = controller.verifying_key();

        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(ConnectionHandler {
                stream: Box::new(stream),
                peer,
                queue,
                identity,
                controller_key: Some(controller_key),
                enrollment_token: None,
                privileged_actions: BTreeMap::new(),
            })
            .await
            .unwrap();
        });

        let (mut socket, _) = connect_async(format!("ws://{address}")).await.unwrap();
        let AuthFrame::Challenge {
            protocol_version,
            session_id,
            challenge,
            host_fingerprint,
        } = receive(&mut socket).await
        else {
            panic!("expected challenge")
        };
        assert_eq!(host_fingerprint, expected_host_fingerprint);

        let public_key = public_key_fingerprint(&controller.verifying_key());
        let authenticate = AuthFrame::Authenticate {
            protocol_version: protocol_version.clone(),
            session_id: session_id.clone(),
            public_key,
            signature: sign_challenge(&controller, &protocol_version, &session_id, &challenge),
            user: None,
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&authenticate).unwrap().into(),
            ))
            .await
            .unwrap();
        let authenticated = receive(&mut socket).await;
        assert!(matches!(authenticated, AuthFrame::Response { response } if response.ok));

        let timestamp = unix_timestamp();
        let nonce = "nonce-000000000001".to_owned();
        let mut command = AgentCommand {
            id: "cmd-settings".into(),
            module: "settings".into(),
            action: "get_system".into(),
            payload: serde_json::Value::Null,
            signature: None,
            user: None,
        };
        command.signature =
            Some(sign_command(&controller, &command, &session_id, 0, timestamp, &nonce).unwrap());
        let command_frame = AuthFrame::Command {
            session_id,
            sequence: 0,
            timestamp,
            nonce,
            command,
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&command_frame).unwrap().into(),
            ))
            .await
            .unwrap();
        let response = receive(&mut socket).await;
        assert!(matches!(response, AuthFrame::Response { response } if response.ok));
        socket.close(None).await.unwrap();
    }
}
