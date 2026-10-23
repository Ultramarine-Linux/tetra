//! Development TCP listener for the session protocol (`agent-ws-serve`).
//!
//! Compiled only with the `dev-listener` feature, so release builds cannot
//! listen on the network. It serves exactly what the Unix socket serves
//! ([`super::local_protocol`]: `hello`, then token-authenticated requests to
//! the same [`AuthService`](crate::auth::AuthService)), so a dashboard or OOBE
//! checkout can run against a real Tetra without the socket, its group, or
//! the service accounts.
//!
//! TCP has no peer credentials, so the listener cannot tell the dashboard
//! from the OOBE, or either from any other local process. Every connection is
//! treated as the one [`ClientKind`] given on the command line. That is why
//! the listener only binds loopback addresses, and why it must never ship:
//! any process on the host can reach it.
//!
//! There is no TLS. The listener is loopback-only and development-only; plain
//! TLS would not identify the local process, while mutual TLS would require a
//! separate client-credential setup. Do not expose it to other hosts.
//! Production uses the Unix socket.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, ensure};
use tokio::{net::TcpListener, sync::Semaphore};

use super::{
    local_protocol::LocalServer,
    local_socket::{MAX_CONNECTIONS, transient_accept_error},
};
use crate::auth::sessions::ClientKind;

/// Default address of `agent-ws-serve`.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7780";

/// Bind `listen`, refusing anything but a loopback address.
pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    ensure_loopback(listen)?;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind the development listener on {listen}"))?;
    Ok(listener)
}

fn ensure_loopback(listen: SocketAddr) -> Result<()> {
    // `to_canonical` so that `::ffff:127.0.0.1` counts as loopback too.
    ensure!(
        listen.ip().to_canonical().is_loopback(),
        "the development listener only binds loopback addresses (127.0.0.0/8 or ::1), not {}",
        listen.ip()
    );
    Ok(())
}

/// Accept connections forever and run the session protocol on each as
/// `client`.
pub async fn serve(listener: TcpListener, server: LocalServer, client: ClientKind) -> Result<()> {
    eprintln!(
        "development listener: serving the session protocol on ws://{} as the {client:?} \
         to any local process",
        listener.local_addr()?
    );
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, address) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) if transient_accept_error(&error) => {
                eprintln!("failed to accept a development client: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error).context("failed to accept a development client"),
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            eprintln!("refusing a development client: {MAX_CONNECTIONS} connections are open");
            continue;
        };
        let server = server.clone();
        tokio::spawn(async move {
            server
                .handle(stream, Some(client), format!("tcp:{address}"))
                .await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent::local_protocol::{ClientFrame, ServerFrame},
        auth::{
            api::{Request, Response},
            testing::TestHost,
        },
    };
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio::net::TcpStream;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

    type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

    #[tokio::test]
    async fn refuses_non_loopback_addresses() {
        for address in [
            "0.0.0.0:7780",
            "192.0.2.1:7780",
            "[::]:7780",
            "[2001:db8::1]:7780",
        ] {
            ensure_loopback(address.parse().unwrap()).unwrap_err();
        }
        for address in [
            "127.0.0.1:7780",
            "127.1.2.3:7780",
            "[::1]:7780",
            "[::ffff:127.0.0.1]:7780",
        ] {
            ensure_loopback(address.parse().unwrap()).unwrap();
        }
        bind("0.0.0.0:0".parse().unwrap()).await.unwrap_err();
    }

    async fn receive(socket: &mut Socket) -> ServerFrame {
        let message = socket.next().await.unwrap().unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    async fn request(
        socket: &mut Socket,
        id: &str,
        token: Option<&str>,
        op: &str,
        params: Value,
    ) -> Response {
        let frame = ClientFrame::Request(Request {
            id: id.into(),
            token: token.map(str::to_owned),
            op: op.into(),
            params,
        });
        let text = serde_json::to_string(&frame).unwrap();
        socket.send(Message::Text(text.into())).await.unwrap();
        let ServerFrame::Response(response) = receive(socket).await else {
            panic!("expected a response to {op}")
        };
        assert_eq!(response.id, id);
        response
    }

    #[tokio::test]
    async fn a_tcp_client_says_hello_and_logs_in() {
        let dir = tempfile::tempdir().unwrap();
        let host = TestHost::new(dir.path()).unwrap();
        host.accounts.add("alice", 1000, &[]);
        host.passwords.set("alice", "hunter2");
        let server = LocalServer {
            auth: host.service.clone(),
            host_fingerprint: "fingerprint".into(),
            shells: crate::agent::shell::ShellServer::system("tetra-shell".into()),
        };
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, server, ClientKind::Oobe));

        let (mut socket, _) = connect_async(format!("ws://{address}/")).await.unwrap();
        let ServerFrame::Hello {
            client,
            host_fingerprint,
            ..
        } = receive(&mut socket).await
        else {
            panic!("expected hello")
        };
        assert_eq!(client, ClientKind::Oobe, "the --client kind applies");
        assert_eq!(host_fingerprint, "fingerprint");

        let wrong = request(
            &mut socket,
            "1",
            None,
            "auth.password",
            json!({"username": "alice", "password": "wrong"}),
        )
        .await;
        assert!(!wrong.ok);

        let login = request(
            &mut socket,
            "2",
            None,
            "auth.password",
            json!({"username": "alice", "password": "hunter2"}),
        )
        .await;
        assert!(login.ok, "{:?}", login.error);
        let result = login.result.unwrap();
        assert_eq!(result["status"], "authenticated", "{result}");
        let token = result["token"].as_str().unwrap();

        let info = request(&mut socket, "3", Some(token), "session.info", json!({})).await;
        assert!(info.ok, "{:?}", info.error);
        assert_eq!(info.result.unwrap()["user"]["username"], "alice");
        socket.close(None).await.unwrap();
    }
}
