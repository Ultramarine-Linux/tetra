//! The session protocol local clients speak over the Unix socket and the
//! development loopback TCP listener.
//!
//! The dashboard and the OOBE send JSON frames over a WebSocket, and every
//! request carries a Tetra-issued session token. Documented in
//! `docs/auth-protocol.md`. The transport decides which client a connection
//! is: the Unix socket from its peer credentials ([`super::peer`]), the
//! development TCP listener from its `--client` flag.
//!
//! Tetra sends `hello` first. The client then sends `request` frames and gets
//! one `response` per request, matched by `id`. Requests run concurrently, so
//! one slow PAM check does not hold up other users of a shared connection;
//! responses may arrive out of order.
//!
//! A connection whose first request is `shell.open` becomes a web shell
//! instead ([`super::shell`]) and carries nothing else.

use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Semaphore, mpsc},
};
use tokio_tungstenite::{
    accept_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

use crate::auth::{
    AuthService,
    api::{ApiError, ErrorCode, PROTOCOL_VERSION, Request, Response},
    sessions::ClientKind,
};

use super::shell::{ShellServer, is_shell_open};

/// Largest WebSocket message or frame a client may send (file writes
/// included). Tungstenite's default is 64 MiB, per in-flight request.
pub(crate) const MAX_MESSAGE_BYTES: usize = 16 << 20;

/// How long a client may take to finish the WebSocket handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Server-side WebSocket limits for Tetra's listeners.
pub(crate) fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
}

/// Requests one connection may have in flight.
const MAX_IN_FLIGHT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    Hello {
        protocol_version: String,
        client: ClientKind,
        host_fingerprint: String,
        setup_required: bool,
        passkeys_available: bool,
    },
    Response(Response),
    /// A frame that could not be parsed, or a refused connection.
    Error {
        error: ApiError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    Request(Request),
}

/// Everything a local connection needs.
#[derive(Clone)]
pub struct LocalServer {
    pub auth: AuthService,
    pub host_fingerprint: String,
    /// Web shells, for connections that start with `shell.open`.
    pub shells: ShellServer,
}

impl LocalServer {
    /// Serve one connection from `client` until it disconnects. `None` is a
    /// peer that is neither the dashboard nor the OOBE: it gets an `error`
    /// frame and is closed. Errors are logged, not returned.
    pub async fn handle<S>(self, stream: S, client: Option<ClientKind>, peer: String)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if let Err(error) = self.run(stream, client).await {
            eprintln!("local peer {peer} closed with error: {error:#}");
        }
    }

    async fn run<S>(self, stream: S, client: Option<ClientKind>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let socket = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            accept_async_with_config(stream, Some(websocket_config())),
        )
        .await
        .context("WebSocket handshake timed out")?
        .context("WebSocket handshake failed")?;
        let (mut sink, mut source) = socket.split();
        let Some(client) = client else {
            let refused = ServerFrame::Error {
                error: ApiError::new(
                    ErrorCode::Forbidden,
                    "this socket only serves the dashboard and the OOBE",
                ),
            };
            sink.send(text(&refused)?).await?;
            sink.close().await.ok();
            anyhow::bail!("refused a peer that is neither the dashboard nor the OOBE");
        };

        let hello = self.auth.hello();
        let flag = |name: &str| hello.get(name).and_then(Value::as_bool).unwrap_or_default();
        sink.send(text(&ServerFrame::Hello {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            client,
            host_fingerprint: self.host_fingerprint.clone(),
            setup_required: flag("setup_required"),
            passkeys_available: flag("passkeys_available"),
        })?)
        .await?;

        // The first request decides what the connection is: `shell.open`
        // turns it into a shell stream, anything else makes it a request
        // connection for good.
        let mut first = None;
        while let Some(message) = source.next().await {
            match message? {
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                Message::Close(_) => break,
                message => {
                    first = Some(message);
                    break;
                }
            }
        }
        let Some(first) = first else {
            sink.close().await.ok();
            return Ok(());
        };
        if let Ok(ClientFrame::Request(request)) = parse(&first)
            && is_shell_open(&request)
        {
            return self
                .shells
                .serve(&self.auth, client, request, sink, source)
                .await;
        }

        let (sender, mut outbox) = mpsc::channel::<ServerFrame>(MAX_IN_FLIGHT);
        let writer = tokio::spawn(async move {
            while let Some(frame) = outbox.recv().await {
                sink.send(text(&frame)?).await?;
            }
            sink.close().await.ok();
            anyhow::Ok(())
        });

        let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let mut next = Some(first);
        loop {
            let message = match next.take() {
                Some(message) => message,
                None => match source.next().await {
                    Some(message) => message?,
                    None => break,
                },
            };
            let frame = match message {
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                message => parse(&message),
            };
            let ClientFrame::Request(request) = match frame {
                Ok(frame) => frame,
                Err(error) => {
                    let error = ApiError::bad_request(format!("invalid frame: {error}"));
                    sender.send(ServerFrame::Error { error }).await.ok();
                    continue;
                }
            };
            let permit = Arc::clone(&in_flight).acquire_owned().await?;
            let auth = self.auth.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let response = auth.handle(client, request).await;
                sender.send(ServerFrame::Response(response)).await.ok();
                drop(permit);
            });
        }
        drop(sender);
        writer.await.context("writer task failed")?
    }
}

/// A client frame from a text or binary message.
fn parse(message: &Message) -> serde_json::Result<ClientFrame> {
    match message {
        Message::Text(text) => serde_json::from_str(text),
        message => serde_json::from_slice(&message.clone().into_data()),
    }
}

pub(crate) fn text(frame: &ServerFrame) -> Result<Message> {
    Ok(Message::Text(serde_json::to_string(frame)?.into()))
}
