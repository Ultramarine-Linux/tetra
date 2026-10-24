//! Local Unix socket transport for clients on the same host (the dashboard
//! container and the server OOBE).
//!
//! This is the only listener `tetra.service` runs: production installs do not
//! listen on the network. Each connection is identified by its peer
//! credentials ([`super::peer`]) and then speaks the session protocol in
//! [`super::local_protocol`]: every request carries a Tetra-issued session
//! token.
//!
//! The socket is normally created by systemd (`tetra.socket`) as
//! `root:tetra 0660`, and handed over through socket activation. When Tetra is
//! started outside systemd it binds the path itself.

use std::{
    env,
    fs::{self, Permissions},
    io::{self, ErrorKind},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, PermissionsExt},
    },
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Socket, Type};
use std::sync::Arc;

use tokio::net::UnixListener;

use super::{local_protocol::LocalServer, peer::PeerPolicy};

/// Default socket path. Matches `ListenStream=` in `systemd/tetra.socket`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/tetra/tetra.sock";
/// First file descriptor passed by systemd socket activation
/// (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: i32 = 3;
/// Mode for a socket Tetra binds itself: owner and group only.
const SOCKET_MODE: u32 = 0o660;
/// Most local connections open at once. Bounds the tasks (and descriptors)
/// any number of idle or stuck clients can pin; the dashboard and the OOBE
/// need a handful.
pub(crate) const MAX_CONNECTIONS: usize = 64;

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
    // sd_listen_fds(3) would set this; without it every child (systemctl,
    // podman under `runuser`, ...) inherits the listener and could accept()
    // dashboard connections.
    socket.set_cloexec(true)?;
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

/// Whether a failed `accept()` is transient. Running out of descriptors or
/// memory, or a client giving up mid-handshake, must not take the whole
/// daemon (and the remote session) down.
pub(crate) fn transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::EINTR
                | libc::EPROTO
        )
    )
}

/// Accept local clients forever, identifying each by its peer credentials
/// under `peers` and running the session protocol on the connection.
pub async fn serve(listener: UnixListener, server: LocalServer, peers: PeerPolicy) -> Result<()> {
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) if transient_accept_error(&error) => {
                eprintln!("failed to accept local client: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error).context("failed to accept local client"),
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            eprintln!("refusing a local client: {MAX_CONNECTIONS} connections are open");
            continue;
        };
        let cred = stream.peer_cred().ok();
        let peer = cred.map_or_else(
            || "unix:unknown".to_owned(),
            |cred| {
                cred.pid().map_or_else(
                    || format!("unix:uid={}", cred.uid()),
                    |pid| format!("unix:uid={},pid={pid}", cred.uid()),
                )
            },
        );
        let server = server.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            // Resolves account names, so off the accept loop.
            let client = cred.and_then(|cred| peers.classify(cred.uid()));
            server.handle(stream, client, peer).await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent::{
            local_protocol::{ClientFrame, ServerFrame},
            peer::{PeerMatch, PeerPolicy},
        },
        auth::{api::Request, sessions::ClientKind, testing::TestHost},
    };
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use std::path::PathBuf;
    use tokio::net::UnixStream;
    use tokio_tungstenite::{WebSocketStream, client_async, tungstenite::Message};

    async fn receive(socket: &mut WebSocketStream<UnixStream>) -> ServerFrame {
        let message = socket.next().await.unwrap().unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    fn serve_as(dir: &Path, dashboard: u32) -> (PathBuf, TestHost) {
        let host = TestHost::new(&dir.join("host")).unwrap();
        let path = dir.join("tetra.sock");
        let server = LocalServer {
            auth: host.service.clone(),
            host_fingerprint: "fingerprint".into(),
            shells: crate::agent::shell::ShellServer::new(
                std::sync::Arc::new(crate::agent::shell::pty::FakeSpawner::new().0),
                crate::agent::shell::ShellLimits::default(),
            ),
        };
        let peers = PeerPolicy {
            dashboard: PeerMatch::Uid(dashboard),
            oobe: PeerMatch::Uid(u32::MAX),
        };
        tokio::spawn(serve(bind(&path).unwrap(), server, peers));
        (path, host)
    }

    fn own_uid() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    #[tokio::test]
    async fn the_dashboard_peer_gets_hello_and_answers() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _host) = serve_as(dir.path(), own_uid());
        let (mut socket, _) =
            client_async("ws://localhost/", UnixStream::connect(&path).await.unwrap())
                .await
                .unwrap();
        let ServerFrame::Hello {
            client,
            setup_required,
            protocol_version,
            ..
        } = receive(&mut socket).await
        else {
            panic!("expected hello")
        };
        assert_eq!(client, ClientKind::Dashboard);
        assert!(setup_required);
        assert_eq!(protocol_version, crate::auth::api::PROTOCOL_VERSION);

        let request = ClientFrame::Request(Request {
            id: "1".into(),
            token: None,
            op: "module.dispatch".into(),
            params: json!({"module": "settings", "action": "get_system"}),
        });
        socket
            .send(Message::Text(
                serde_json::to_string(&request).unwrap().into(),
            ))
            .await
            .unwrap();
        let ServerFrame::Response(response) = receive(&mut socket).await else {
            panic!("expected response")
        };
        assert_eq!(response.id, "1");
        assert!(!response.ok, "module commands need a token");
        socket.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn other_peers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _host) = serve_as(dir.path(), own_uid().wrapping_add(1));
        let (mut socket, _) =
            client_async("ws://localhost/", UnixStream::connect(&path).await.unwrap())
                .await
                .unwrap();
        assert!(matches!(
            receive(&mut socket).await,
            ServerFrame::Error { .. }
        ));
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
