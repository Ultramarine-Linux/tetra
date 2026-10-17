//! Local Unix socket transport for clients on the same host (the dashboard
//! container and the server OOBE).
//!
//! This is the only listener `tetra.service` runs: production installs do not
//! listen on the network. The socket carries the same authenticated WebSocket
//! protocol as [`super::websocket_server`], so clients only swap TCP for a
//! Unix stream.
//!
//! The socket is normally created by systemd (`tetra.socket`) as
//! `root:tetra 0660`, and handed over through socket activation. When Tetra is
//! started outside systemd it binds the path itself.

use std::{
    env,
    fs::{self, Permissions},
    io::ErrorKind,
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, PermissionsExt},
    },
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Socket, Type};
use tokio::net::{UnixListener, UnixStream};

use super::websocket_server::ServerState;

/// Default socket path. Matches `ListenStream=` in `systemd/tetra.socket`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/tetra/tetra.sock";
/// First file descriptor passed by systemd socket activation
/// (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: i32 = 3;
/// Mode for a socket Tetra binds itself: owner and group only.
const SOCKET_MODE: u32 = 0o660;

/// Return the systemd-activated listener if one was passed to this process,
/// otherwise bind `path`.
pub fn listener(path: &Path) -> Result<UnixListener> {
    let count = activated_fd_count(
        env::var("LISTEN_PID").ok().as_deref(),
        env::var("LISTEN_FDS").ok().as_deref(),
        std::process::id(),
    )?;
    if count == 0 {
        return bind(path);
    }
    // SAFETY: `activated_fd_count` verified that systemd passed exactly one
    // descriptor to this process (LISTEN_PID matches our pid), and by the
    // sd_listen_fds(3) protocol it is open at fd 3. `listener` is called once
    // at startup, so ownership of the descriptor is taken exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(LISTEN_FDS_START) };
    let socket = Socket::from(fd);
    ensure!(
        socket.domain()? == Domain::UNIX
            && socket.r#type()? == Type::STREAM
            && socket.is_listener()?,
        "socket-activated descriptor is not a listening Unix stream socket"
    );
    socket.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std::os::unix::net::UnixListener::from(OwnedFd::from(
        socket,
    )))?;
    eprintln!("using socket-activated listener for local clients");
    Ok(listener)
}

/// Parse the socket activation environment. Returns 0 when this process was
/// not socket-activated.
fn activated_fd_count(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    pid: u32,
) -> Result<usize> {
    let (Some(listen_pid), Some(listen_fds)) = (listen_pid, listen_fds) else {
        return Ok(0);
    };
    // The variables are inherited by children; only the named pid owns the fds.
    if listen_pid.trim().parse::<u32>().ok() != Some(pid) {
        return Ok(0);
    }
    let count = listen_fds
        .trim()
        .parse::<usize>()
        .context("invalid LISTEN_FDS")?;
    if count > 1 {
        bail!("expected one socket-activated listener, got {count}");
    }
    Ok(count)
}

/// Bind `path` for runs outside systemd, replacing a stale socket left by a
/// previous run. Refuses to remove anything that is not a socket.
fn bind(path: &Path) -> Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)
            .with_context(|| format!("failed to remove stale socket `{}`", path.display()))?,
        Ok(_) => bail!("`{}` exists and is not a socket", path.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect `{}`", path.display()));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create `{}`", parent.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind local socket `{}`", path.display()))?;
    fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("failed to set permissions on `{}`", path.display()))?;
    eprintln!("bound local socket {}", path.display());
    Ok(listener)
}

/// Accept local clients forever, running the authenticated WebSocket protocol
/// on each connection.
pub async fn serve(listener: UnixListener, state: ServerState) -> Result<()> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept local client")?;
        let peer = peer_label(&stream);
        tokio::spawn(state.clone().handle(stream, peer));
    }
}

/// Describe a local peer for logs. Credentials are informational only here.
fn peer_label(stream: &UnixStream) -> String {
    stream.peer_cred().map_or_else(
        |_| "unix:unknown".to_owned(),
        |cred| {
            cred.pid().map_or_else(
                || format!("unix:uid={}", cred.uid()),
                |pid| format!("unix:uid={},pid={pid}", cred.uid()),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        AgentCommand,
        crypto::{public_key_fingerprint, sign_challenge, sign_command},
        protocol::{AuthFrame, unix_timestamp},
    };
    use ed25519_dalek::SigningKey;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{WebSocketStream, client_async, tungstenite::Message};

    async fn exchange(
        socket: &mut WebSocketStream<UnixStream>,
        frame: Option<&AuthFrame>,
    ) -> AuthFrame {
        if let Some(frame) = frame {
            let text = serde_json::to_string(frame).unwrap();
            socket.send(Message::Text(text.into())).await.unwrap();
        }
        let message = socket.next().await.unwrap().unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn local_client_can_dispatch_a_module_command() {
        let controller = SigningKey::from_bytes(&[17_u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tetra.sock");
        let state = ServerState::load(
            &dir.path().join("identity"),
            Some(public_key_fingerprint(&controller.verifying_key())),
            None,
        )
        .unwrap();
        tokio::spawn(serve(bind(&path).unwrap(), state));

        let stream = UnixStream::connect(&path).await.unwrap();
        let (mut socket, _) = client_async("ws://localhost/", stream).await.unwrap();
        let AuthFrame::Challenge {
            protocol_version,
            session_id,
            challenge,
            ..
        } = exchange(&mut socket, None).await
        else {
            panic!("expected challenge")
        };
        let authenticate = AuthFrame::Authenticate {
            protocol_version: protocol_version.clone(),
            session_id: session_id.clone(),
            public_key: public_key_fingerprint(&controller.verifying_key()),
            signature: sign_challenge(&controller, &protocol_version, &session_id, &challenge),
            user: None,
        };
        assert!(matches!(
            exchange(&mut socket, Some(&authenticate)).await,
            AuthFrame::Response { response } if response.ok
        ));

        let timestamp = unix_timestamp();
        let nonce = "nonce-000000000001".to_owned();
        let mut command = AgentCommand {
            id: "cmd-settings".into(),
            module: "settings".into(),
            action: "get_system".into(),
            ..Default::default()
        };
        command.signature =
            Some(sign_command(&controller, &command, &session_id, 0, timestamp, &nonce).unwrap());
        let command = AuthFrame::Command {
            session_id,
            sequence: 0,
            timestamp,
            nonce,
            command,
        };
        let AuthFrame::Response { response } = exchange(&mut socket, Some(&command)).await else {
            panic!("expected command response")
        };
        assert!(response.ok);
        assert_eq!(response.id, "cmd-settings");
        socket.close(None).await.unwrap();
    }

    #[test]
    fn not_activated_without_environment() {
        assert_eq!(activated_fd_count(None, None, 42).unwrap(), 0);
        assert_eq!(activated_fd_count(Some("42"), None, 42).unwrap(), 0);
    }

    #[test]
    fn ignores_activation_meant_for_another_process() {
        assert_eq!(activated_fd_count(Some("7"), Some("1"), 42).unwrap(), 0);
    }

    #[test]
    fn accepts_one_activated_listener() {
        assert_eq!(activated_fd_count(Some("42"), Some("1"), 42).unwrap(), 1);
        activated_fd_count(Some("42"), Some("2"), 42).unwrap_err();
        activated_fd_count(Some("42"), Some("x"), 42).unwrap_err();
    }

    #[tokio::test]
    async fn bind_replaces_stale_socket_and_restricts_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/tetra.sock");
        drop(bind(&path).unwrap());
        // The first listener left its socket file behind, like a crashed run.
        let _listener = bind(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE);
    }

    #[tokio::test]
    async fn bind_refuses_to_replace_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tetra.sock");
        fs::write(&path, "not a socket").unwrap();
        bind(&path).unwrap_err();
    }
}
