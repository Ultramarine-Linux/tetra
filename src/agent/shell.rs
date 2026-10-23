//! The web shell: a local connection that became a terminal.
//!
//! The dashboard runs in a container and never starts host processes. To
//! open a shell for a signed-in user it asks for a ticket (`shell.ticket`,
//! [`crate::auth::shell`]) on its normal connection, opens a second
//! connection to the same socket and sends `shell.open {ticket, cols, rows}`
//! as that connection's first request. Tetra (root) redeems the ticket,
//! starts the user's login shell on a PTY it owns ([`pty`]), answers with a
//! normal response, and from then on the connection carries only the shell
//! ([`frames`]): binary messages are terminal bytes both ways, text messages
//! are small JSON control frames (`resize` from the dashboard, `exit` from
//! Tetra). The dashboard only pipes bytes between the browser and the
//! socket. There is no other listener.
//!
//! A shell ends when the shell exits, the dashboard closes the connection,
//! its session ends (checked every [`ShellLimits::check_interval`]: logout,
//! revocation, expiry, a locked or renamed account, a removed permission),
//! nothing was typed for [`ShellLimits::idle_timeout`] (output does not
//! count), or it has been open for [`ShellLimits::max_lifetime`]. Typing
//! counts as using the session, so a session stays alive while its shell is
//! used, up to the session's absolute lifetime.
//! Each user may have [`ShellLimits::per_user`] shells, the host
//! [`ShellLimits::total`]. Opening and closing are recorded in the action
//! log (module `shell`, actions `open` and `close`).

pub mod frames;
pub mod pty;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
    time::Instant,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Bytes, Message},
};

use crate::auth::{
    AuthService,
    api::{ApiError, ErrorCode, Request, Response, params},
    sessions::{ClientKind, hex},
    shell::ShellGrant,
};

use self::{
    frames::{ClientControl, ExitReason, OpenParams, ServerControl, WindowSize},
    pty::{PtySpawner, Resize, ShellProcess, ShellRequest, SpawnedShell, SystemdRun},
};
use super::local_protocol::{ServerFrame, text};

/// Largest input message: one paste. Larger ones end the shell.
pub const MAX_INPUT_BYTES: usize = 1 << 20;
/// Bytes read from the PTY per output message.
const OUTPUT_CHUNK: usize = 16 * 1024;
/// Output messages queued for the dashboard. When it reads slower than the
/// shell writes, the shell blocks on its terminal instead of Tetra buffering.
const OUTBOX: usize = 16;
/// How long the shell may take to exit after its terminal closed, and the
/// output to drain after it exited.
const EXIT_GRACE: Duration = Duration::from_secs(2);
/// How long the last frames may take to reach the dashboard.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// How many shells may run, and when they end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellLimits {
    /// Shells one user may have open at once.
    pub per_user: usize,
    /// Shells the host runs at once.
    pub total: usize,
    /// A shell without input for this long ends. Only input counts: a
    /// forgotten `tail -f` or `watch` must not keep a shell alive.
    pub idle_timeout: Duration,
    /// A shell ends after this long however it is used, so no shell outlives
    /// a working day.
    pub max_lifetime: Duration,
    /// How often a shell's session is checked.
    pub check_interval: Duration,
}

impl Default for ShellLimits {
    fn default() -> Self {
        Self {
            per_user: 4,
            total: 16,
            idle_timeout: Duration::from_mins(30),
            max_lifetime: Duration::from_hours(4),
            check_interval: Duration::from_secs(5),
        }
    }
}

/// Opens and runs shells. Cheap to clone.
#[derive(Clone)]
pub struct ShellServer {
    inner: Arc<Inner>,
}

struct Inner {
    spawner: Arc<dyn PtySpawner>,
    limits: ShellLimits,
    open: Mutex<Open>,
}

/// The shells open right now.
#[derive(Default)]
struct Open {
    /// Per UID.
    per_user: HashMap<u32, usize>,
    /// Their units (`tetra-shell-….service`), so the startup sweep leaves
    /// them alone.
    units: HashSet<String>,
}

/// A shell's place under [`ShellLimits`], given back when dropped.
struct Slot {
    inner: Arc<Inner>,
    uid: u32,
    unit: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self.inner.lock();
        open.units.remove(&self.unit);
        if let Some(count) = open.per_user.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.per_user.remove(&self.uid);
            }
        }
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Open> {
        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How a shell ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct End {
    reason: ExitReason,
    status: Option<i32>,
}

impl End {
    const fn because(reason: ExitReason) -> Self {
        Self {
            reason,
            status: None,
        }
    }
}

/// How the input side stopped.
enum InputEnd {
    /// The dashboard closed the connection (or it broke).
    Closed,
    /// An input message over [`MAX_INPUT_BYTES`].
    TooLarge,
    /// The terminal is gone; the shell is exiting.
    TerminalClosed,
}

/// How the output side stopped.
enum OutputEnd {
    /// Nothing holds the terminal open any more: the shell is exiting.
    HungUp,
    /// The connection to the dashboard is gone.
    ClientGone,
}

impl ShellServer {
    #[must_use]
    pub fn new(spawner: Arc<dyn PtySpawner>, limits: ShellLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                spawner,
                limits,
                open: Mutex::new(Open::default()),
            }),
        }
    }

    /// Shells through `systemd-run --pty` with the PAM service
    /// `pam_service`, under the default limits.
    #[must_use]
    pub fn system(pam_service: String) -> Self {
        Self::new(
            Arc::new(SystemdRun::new(pam_service)),
            ShellLimits::default(),
        )
    }

    /// Shells open right now.
    #[must_use]
    pub fn open_shells(&self) -> usize {
        self.inner.lock().per_user.values().sum()
    }

    /// Stop the web shell units a previous run of Tetra left behind (it
    /// crashed or was restarted), leaving this run's own shells alone.
    /// Best-effort and logged; see [`pty::stop_leftover_units`]. For
    /// startup.
    pub async fn stop_leftover_units(&self) {
        self.stop_leftover_units_with(pty::SYSTEMCTL.as_ref()).await;
    }

    async fn stop_leftover_units_with(&self, systemctl: &std::path::Path) {
        pty::stop_leftover_units(systemctl, |unit| self.inner.lock().units.contains(unit)).await;
    }

    /// Take a slot for a shell of `uid` in `unit` (without `.service`).
    fn acquire(&self, uid: u32, unit: &str) -> Result<Slot, ApiError> {
        let limits = self.inner.limits;
        let mut open = self.inner.lock();
        let total: usize = open.per_user.values().sum();
        let mine = open.per_user.get(&uid).copied().unwrap_or_default();
        if mine >= limits.per_user {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                format!(
                    "you already have {} shells open; close one first",
                    limits.per_user
                ),
            ));
        }
        if total >= limits.total {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                "too many shells are open on this server; try again later",
            ));
        }
        open.per_user.insert(uid, mine.saturating_add(1));
        // Before the unit exists, so the startup sweep never sees it as a
        // leftover.
        let unit = format!("{unit}.service");
        open.units.insert(unit.clone());
        drop(open);
        Ok(Slot {
            inner: Arc::clone(&self.inner),
            uid,
            unit,
        })
    }

    /// Serve `request` (a `shell.open`, the connection's first request)
    /// from `client`: answer it, then run the shell on this connection until
    /// it ends.
    ///
    /// # Errors
    /// Fails only when the connection breaks before the answer is sent.
    pub(crate) async fn serve<S>(
        &self,
        auth: &AuthService,
        client: ClientKind,
        request: Request,
        mut sink: SplitSink<WebSocketStream<S>, Message>,
        source: SplitStream<WebSocketStream<S>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Redeeming reads the session and user stores, and starting the shell
        // runs systemd-run: both block, so keep them off the async workers.
        let opened = {
            let (this, auth, request) = (self.clone(), auth.clone(), request.clone());
            tokio::task::spawn_blocking(move || this.open(&auth, client, &request))
                .await
                .unwrap_or_else(|error| Err(anyhow::anyhow!(error).into()))
        };
        let (grant, slot, shell, unit, size) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                let response = Response::new(request.id, Err(error));
                sink.send(text(&ServerFrame::Response(response))?).await?;
                sink.close().await.ok();
                return Ok(());
            }
        };
        let result = json!({
            "uid": grant.uid,
            "username": grant.username,
            "unit": format!("{unit}.service"),
            "cols": size.cols,
            "rows": size.rows,
            "idle_timeout": self.inner.limits.idle_timeout.as_secs(),
            "max_lifetime": self.inner.limits.max_lifetime.as_secs(),
        });
        let answered = sink
            .send(text(&ServerFrame::Response(Response::new(
                request.id.clone(),
                Ok(result),
            )))?)
            .await;
        let end = if answered.is_ok() {
            self.run(auth, &grant, shell, sink, source).await
        } else {
            let mut process = shell.process;
            process.terminate().await;
            End::because(ExitReason::ClientClosed)
        };
        let status = end
            .status
            .map(|status| format!("; status {status}"))
            .unwrap_or_default();
        let detail = format!("unit {unit}.service; {:?}{status}", end.reason);
        let auth = auth.clone();
        tokio::task::spawn_blocking(move || {
            auth.record_shell(&grant, &request.id, "close", Ok(()), Some(detail));
        })
        .await
        .ok();
        // Only now does the shell stop counting: once a caller sees it gone,
        // its close is in the action log.
        drop(slot);
        Ok(())
    }

    /// Redeem the ticket, take a slot and start the shell.
    fn open(
        &self,
        auth: &AuthService,
        client: ClientKind,
        request: &Request,
    ) -> Result<(ShellGrant, Slot, SpawnedShell, String, WindowSize), ApiError> {
        let params: OpenParams = params(&request.params)?;
        let size = WindowSize::new(params.cols, params.rows).map_err(ApiError::bad_request)?;
        let grant = auth.redeem_shell_ticket(client, &params.ticket)?;
        let unit = unit_name(grant.uid);
        let slot = self.acquire(grant.uid, &unit)?;
        let spawned = self.inner.spawner.spawn(&ShellRequest {
            grant: &grant,
            unit: &unit,
            size,
        });
        let detail = Some(format!("unit {unit}.service"));
        match spawned {
            Ok(shell) => {
                eprintln!("opened web shell {unit} for `{}`", grant.username);
                auth.record_shell(&grant, &request.id, "open", Ok(()), detail);
                Ok((grant, slot, shell, unit, size))
            }
            Err(error) => {
                eprintln!(
                    "failed to start a web shell for `{}`: {error:#}",
                    grant.username
                );
                auth.record_shell(
                    &grant,
                    &request.id,
                    "open",
                    Err("the shell could not be started"),
                    detail,
                );
                Err(ApiError::new(
                    ErrorCode::Internal,
                    "the shell could not be started; see the Tetra journal",
                ))
            }
        }
    }

    /// Pump bytes between the connection and the shell until it ends, then
    /// stop the shell and tell the dashboard why.
    async fn run<S>(
        &self,
        auth: &AuthService,
        grant: &ShellGrant,
        shell: SpawnedShell,
        mut sink: SplitSink<WebSocketStream<S>, Message>,
        source: SplitStream<WebSocketStream<S>>,
    ) -> End
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let SpawnedShell {
            io,
            resizer,
            mut process,
        } = shell;
        let (pty_read, pty_write) = tokio::io::split(io);
        let (outbox, mut outgoing) = mpsc::channel::<Message>(OUTBOX);
        let mut writer = tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
            sink.close().await.ok();
        });
        let typed = Arc::new(AtomicBool::new(false));
        let mut pumps = Pumps {
            input: tokio::spawn(pump_input(source, pty_write, resizer, Arc::clone(&typed))),
            output: tokio::spawn(pump_output(pty_read, outbox.clone())),
            input_done: false,
            output_done: false,
            typed,
        };
        let end = self
            .supervise(auth, grant, &mut pumps, process.as_mut())
            .await;
        stop(&mut pumps.input, pumps.input_done).await;
        process.terminate().await;
        if !pumps.output_done
            && tokio::time::timeout(EXIT_GRACE, &mut pumps.output)
                .await
                .is_err()
        {
            stop(&mut pumps.output, false).await;
        }
        // The exit frame waits behind queued output, and both behind a
        // dashboard that may have stopped reading: bound the whole, so the
        // shell's slot is always given back.
        let exit = if end.reason == ExitReason::ClientClosed {
            None
        } else {
            serde_json::to_string(&ServerControl::Exit {
                status: end.status,
                reason: end.reason,
            })
            .ok()
        };
        let close = async {
            if let Some(frame) = exit {
                outbox.send(Message::Text(frame.into())).await.ok();
            }
            drop(outbox);
            (&mut writer).await.ok();
        };
        if tokio::time::timeout(CLOSE_GRACE, close).await.is_err() {
            // The dashboard stopped reading; drop the connection.
            stop(&mut writer, false).await;
        }
        eprintln!(
            "closed the web shell of `{}` ({:?})",
            grant.username, end.reason
        );
        end
    }

    /// Wait until the shell exits, the connection closes, the session ends or
    /// the shell has been idle too long.
    async fn supervise(
        &self,
        auth: &AuthService,
        grant: &ShellGrant,
        pumps: &mut Pumps,
        process: &mut dyn ShellProcess,
    ) -> End {
        let limits = self.inner.limits;
        let mut ticker = tokio::time::interval(limits.check_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate.
        ticker.tick().await;
        let started = Instant::now();
        let mut last_input = started;
        loop {
            tokio::select! {
                ended = &mut pumps.input, if !pumps.input_done => {
                    pumps.input_done = true;
                    match ended {
                        // The shell is exiting; the other branches see it.
                        Ok(InputEnd::TerminalClosed) => {}
                        Ok(InputEnd::TooLarge) => return End::because(ExitReason::ProtocolError),
                        Ok(InputEnd::Closed) | Err(_) => return End::because(ExitReason::ClientClosed),
                    }
                }
                ended = &mut pumps.output, if !pumps.output_done => {
                    pumps.output_done = true;
                    if !matches!(ended, Ok(OutputEnd::HungUp)) {
                        return End::because(ExitReason::ClientClosed);
                    }
                    // The terminal hung up: the shell is exiting.
                    let status = tokio::time::timeout(EXIT_GRACE, process.wait()).await;
                    return End {
                        reason: ExitReason::Exited,
                        status: status.ok().and_then(Result::ok).flatten(),
                    };
                }
                status = process.wait() => {
                    // Let what it wrote last reach the dashboard.
                    if !pumps.output_done
                        && tokio::time::timeout(EXIT_GRACE, &mut pumps.output).await.is_ok()
                    {
                        pumps.output_done = true;
                    }
                    return End { reason: ExitReason::Exited, status: status.ok().flatten() };
                }
                _ = ticker.tick() => {
                    let touch = pumps.typed.swap(false, Ordering::Relaxed);
                    if touch {
                        last_input = Instant::now();
                    }
                    let checked = {
                        let (auth, grant) = (auth.clone(), grant.clone());
                        tokio::task::spawn_blocking(move || auth.check_shell_session(&grant, touch))
                            .await
                            .unwrap_or_else(|error| Err(anyhow::anyhow!(error).into()))
                    };
                    if let Err(error) = checked {
                        eprintln!(
                            "ending the web shell of `{}`: {}",
                            grant.username, error.message
                        );
                        return End::because(ExitReason::SessionEnded);
                    }
                    if last_input.elapsed() >= limits.idle_timeout {
                        return End::because(ExitReason::IdleTimeout);
                    }
                    if started.elapsed() >= limits.max_lifetime {
                        return End::because(ExitReason::MaxLifetime);
                    }
                }
            }
        }
    }
}

/// The two tasks moving bytes, and what the input side saw.
struct Pumps {
    input: JoinHandle<InputEnd>,
    output: JoinHandle<OutputEnd>,
    input_done: bool,
    output_done: bool,
    /// Set by the input side on every keystroke or resize.
    typed: Arc<AtomicBool>,
}

/// Abort `task` (unless it already finished) and wait until it is gone, so
/// the PTY descriptors it holds are closed.
async fn stop<T>(task: &mut JoinHandle<T>, finished: bool) {
    if !finished {
        task.abort();
        task.await.ok();
    }
}

/// Dashboard to shell: input bytes and resizes.
async fn pump_input<S, W>(
    mut source: SplitStream<WebSocketStream<S>>,
    mut terminal: W,
    resizer: Box<dyn Resize>,
    typed: Arc<AtomicBool>,
) -> InputEnd
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Some(message) = source.next().await {
        match message {
            Ok(Message::Binary(bytes)) => {
                if bytes.len() > MAX_INPUT_BYTES {
                    return InputEnd::TooLarge;
                }
                typed.store(true, Ordering::Relaxed);
                if terminal.write_all(&bytes).await.is_err() {
                    return InputEnd::TerminalClosed;
                }
            }
            Ok(Message::Text(frame)) => {
                if let Some(ClientControl::Resize { cols, rows }) = ClientControl::parse(&frame) {
                    typed.store(true, Ordering::Relaxed);
                    resizer.resize(WindowSize { cols, rows }).ok();
                }
            }
            Ok(Message::Close(_)) | Err(_) => return InputEnd::Closed,
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
        }
    }
    InputEnd::Closed
}

/// Shell to dashboard: output bytes, until the terminal hangs up.
async fn pump_output<R: AsyncRead + Unpin>(
    mut terminal: R,
    outbox: mpsc::Sender<Message>,
) -> OutputEnd {
    let mut buffer = vec![0_u8; OUTPUT_CHUNK];
    loop {
        let read = match terminal.read(&mut buffer).await {
            Ok(0) | Err(_) => return OutputEnd::HungUp,
            Ok(read) => read,
        };
        let chunk = Bytes::copy_from_slice(buffer.get(..read).unwrap_or_default());
        if outbox.send(Message::Binary(chunk)).await.is_err() {
            return OutputEnd::ClientGone;
        }
    }
}

/// A fresh transient unit name for a shell of `uid`.
fn unit_name(uid: u32) -> String {
    let mut random = [0_u8; 6];
    rand::fill(&mut random);
    format!("{}{uid}-{}", pty::UNIT_PREFIX, hex(&random))
}

/// Whether `request` asks to turn its connection into a shell.
#[must_use]
pub fn is_shell_open(request: &Request) -> bool {
    request.op == "shell.open"
}

#[cfg(test)]
mod tests {
    use super::{
        pty::{FakeShell, FakeSpawner},
        *,
    };
    use crate::{
        agent::{
            local_protocol::{ClientFrame, LocalServer},
            local_socket,
            peer::{PeerMatch, PeerPolicy},
        },
        auth::{audit::Origin, testing::TestHost},
    };
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use tokio::{net::UnixStream, sync::mpsc::UnboundedReceiver};
    use tokio_tungstenite::client_async;

    type Socket = WebSocketStream<UnixStream>;

    struct Harness {
        _dir: tempfile::TempDir,
        path: PathBuf,
        host: TestHost,
        shells: UnboundedReceiver<FakeShell>,
        server: ShellServer,
        spawner: Arc<FakeSpawner>,
    }

    fn fast() -> ShellLimits {
        ShellLimits {
            check_interval: Duration::from_millis(20),
            ..ShellLimits::default()
        }
    }

    fn harness(limits: ShellLimits) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let host = TestHost::new(&dir.path().join("host")).unwrap();
        host.accounts.add("alice", 1000, &[]);
        host.accounts.add("bob", 1002, &[]);
        host.passwords.set("alice", "hunter2");
        host.passwords.set("bob", "hunter2");
        let (spawner, shells) = FakeSpawner::new();
        let spawner = Arc::new(spawner);
        let server = ShellServer::new(Arc::clone(&spawner) as _, limits);
        let path = dir.path().join("tetra.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let local = LocalServer {
            auth: host.service.clone(),
            host_fingerprint: "fingerprint".into(),
            shells: server.clone(),
        };
        let peers = PeerPolicy {
            dashboard: PeerMatch::Uid(nix::unistd::getuid().as_raw()),
            oobe: PeerMatch::Uid(u32::MAX),
        };
        tokio::spawn(local_socket::serve(listener, local, peers));
        Harness {
            _dir: dir,
            path,
            host,
            shells,
            server,
            spawner,
        }
    }

    async fn request(host: &TestHost, token: Option<&str>, op: &str, params: Value) -> Value {
        let response = host
            .service
            .handle(
                ClientKind::Dashboard,
                Request {
                    id: op.into(),
                    token: token.map(str::to_owned),
                    op: op.into(),
                    params,
                },
            )
            .await;
        assert!(response.ok, "{op}: {:?}", response.error);
        response.result.unwrap()
    }

    async fn login(host: &TestHost, username: &str) -> String {
        let result = request(
            host,
            None,
            "auth.password",
            json!({"username": username, "password": "hunter2"}),
        )
        .await;
        result["token"].as_str().unwrap().to_owned()
    }

    async fn ticket(host: &TestHost, token: &str) -> String {
        let result = request(host, Some(token), "shell.ticket", Value::Null).await;
        result["ticket"].as_str().unwrap().to_owned()
    }

    async fn connect(path: &Path) -> Socket {
        let stream = UnixStream::connect(path).await.unwrap();
        let (mut socket, _) = client_async("ws://localhost/", stream).await.unwrap();
        // hello
        socket.next().await.unwrap().unwrap();
        socket
    }

    async fn send_request(socket: &mut Socket, op: &str, params: Value) {
        let frame = ClientFrame::Request(Request {
            id: "open-1".into(),
            token: None,
            op: op.into(),
            params,
        });
        socket
            .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
            .await
            .unwrap();
    }

    async fn response(socket: &mut Socket) -> Response {
        let message = socket.next().await.unwrap().unwrap();
        match serde_json::from_str(message.to_text().unwrap()).unwrap() {
            ServerFrame::Response(response) => response,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    async fn open(socket: &mut Socket, ticket: &str) -> Response {
        send_request(
            socket,
            "shell.open",
            json!({"ticket": ticket, "cols": 100, "rows": 30}),
        )
        .await;
        response(socket).await
    }

    /// The exit frame, skipping output still in flight.
    async fn exit_frame(socket: &mut Socket) -> ServerControl {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
                .await
                .expect("no exit frame")
                .unwrap()
                .unwrap();
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        for _ in 0..250 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn a_shell_pipes_bytes_resizes_and_reports_its_exit() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        let opened = open(&mut socket, &ticket).await;
        assert!(opened.ok, "{:?}", opened.error);
        let result = opened.result.unwrap();
        assert_eq!(result["uid"], 1000);
        assert_eq!(result["username"], "alice");
        assert_eq!(result["cols"], 100);

        let mut shell = h.shells.recv().await.unwrap();
        assert_eq!(shell.grant.uid, 1000);
        assert_eq!(shell.grant.shell, "/bin/bash");
        assert_eq!(
            shell.size,
            WindowSize {
                cols: 100,
                rows: 30
            }
        );
        assert!(shell.unit.starts_with("tetra-shell-1000-"));
        assert_eq!(h.server.open_shells(), 1);

        socket
            .send(Message::Binary(Bytes::from_static(b"ls\n")))
            .await
            .unwrap();
        let mut typed = [0_u8; 3];
        shell.terminal.read_exact(&mut typed).await.unwrap();
        assert_eq!(&typed, b"ls\n");

        shell.terminal.write_all(b"file\r\n").await.unwrap();
        let Message::Binary(output) = socket.next().await.unwrap().unwrap() else {
            panic!("expected output");
        };
        assert_eq!(&output[..], b"file\r\n");

        socket
            .send(Message::Text(
                r#"{"type":"resize","cols":120,"rows":40}"#.into(),
            ))
            .await
            .unwrap();
        // Unknown and invalid control frames are ignored.
        socket
            .send(Message::Text(r#"{"type":"future"}"#.into()))
            .await
            .unwrap();
        socket
            .send(Message::Text(
                r#"{"type":"resize","cols":0,"rows":40}"#.into(),
            ))
            .await
            .unwrap();
        let resizes = Arc::clone(&shell.resizes);
        until(|| !resizes.lock().unwrap().is_empty()).await;
        assert_eq!(
            *resizes.lock().unwrap(),
            [WindowSize {
                cols: 120,
                rows: 40
            }]
        );

        shell.exit(Some(3));
        drop(shell.terminal);
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: Some(3),
                reason: ExitReason::Exited
            }
        );
        let server = h.server.clone();
        until(|| server.open_shells() == 0).await;

        let log = h
            .host
            .service
            .audit()
            .recent(10, Some(Origin::Local))
            .unwrap();
        let shell_entries: Vec<_> = log.iter().filter(|e| e.module == "shell").collect();
        assert_eq!(shell_entries.len(), 2, "{log:?}");
        assert_eq!(shell_entries[0].action, "close");
        assert_eq!(shell_entries[1].action, "open");
        for entry in shell_entries {
            assert!(entry.ok);
            assert_eq!(entry.username.as_deref(), Some("alice"));
            assert_eq!(entry.command_id, "open-1");
            assert!(
                entry
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("tetra-shell-1000-")
            );
        }
    }

    #[tokio::test]
    async fn tickets_work_once_and_only_on_a_fresh_connection() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;

        // Not the first request on its connection.
        let mut socket = connect(&h.path).await;
        send_request(&mut socket, "session.info", Value::Null).await;
        response(&mut socket).await;
        let refused = open(&mut socket, &ticket).await;
        assert_eq!(refused.error.unwrap().code, ErrorCode::BadRequest);

        // The ticket was not used up by that, so it still opens a shell.
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let _shell = h.shells.recv().await.unwrap();

        let mut replay = connect(&h.path).await;
        let replayed = open(&mut replay, &ticket).await;
        assert_eq!(replayed.error.unwrap().code, ErrorCode::InvalidCredentials);
        // A refused shell.open closes the connection.
        assert!(matches!(
            replay.next().await,
            None | Some(Ok(Message::Close(_)) | Err(_))
        ));

        let mut bad = connect(&h.path).await;
        send_request(&mut bad, "shell.open", json!({"ticket": "x", "cols": 0})).await;
        assert_eq!(
            response(&mut bad).await.error.unwrap().code,
            ErrorCode::BadRequest
        );
    }

    #[tokio::test]
    async fn ending_the_session_ends_its_shell() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();

        request(&h.host, Some(&token), "session.logout", Value::Null).await;
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: None,
                reason: ExitReason::SessionEnded
            }
        );
        assert!(shell.is_terminated());
        let server = h.server.clone();
        until(|| server.open_shells() == 0).await;
    }

    #[tokio::test]
    async fn locking_the_account_ends_its_shell() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        h.host.accounts.update("alice", |account| {
            account.shadow = crate::auth::accounts::ShadowState::Locked;
        });
        assert!(matches!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                reason: ExitReason::SessionEnded,
                ..
            }
        ));
        assert!(shell.is_terminated());
    }

    #[tokio::test]
    async fn revoking_the_session_ends_its_shell() {
        let mut h = harness(fast());
        h.host.accounts.add("root-admin", 1001, &["wheel"]);
        h.host.passwords.set("root-admin", "hunter2");
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();

        let admin = login(&h.host, "root-admin").await;
        request(
            &h.host,
            Some(&admin),
            "admin.sessions_revoke",
            json!({"uid": 1000}),
        )
        .await;
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: None,
                reason: ExitReason::SessionEnded
            }
        );
        assert!(shell.is_terminated());
    }

    #[tokio::test]
    async fn an_expired_session_ends_its_shell() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();

        // Past the absolute lifetime: typing cannot keep it alive.
        let policy = crate::auth::sessions::SessionPolicy::default();
        h.host.clock.advance(policy.lifetime.saturating_add(1));
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: None,
                reason: ExitReason::SessionEnded
            }
        );
        assert!(shell.is_terminated());
    }

    #[tokio::test]
    async fn shells_end_at_their_maximum_lifetime_even_when_used() {
        let mut h = harness(ShellLimits {
            max_lifetime: Duration::from_millis(150),
            ..fast()
        });
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        // Keep typing; the lifetime still ends it.
        for _ in 0..20 {
            let sent = socket.send(Message::Binary(b"x".to_vec().into())).await;
            if sent.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: None,
                reason: ExitReason::MaxLifetime
            }
        );
        assert!(shell.is_terminated());
    }

    #[tokio::test]
    async fn closing_the_connection_stops_the_shell() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        socket.close(None).await.unwrap();
        drop(socket);
        let terminated = Arc::clone(&shell.terminated);
        until(|| terminated.load(Ordering::SeqCst)).await;
        let server = h.server.clone();
        until(|| server.open_shells() == 0).await;
        let host = &h.host;
        until(|| {
            host.service
                .audit()
                .recent(1, None)
                .unwrap()
                .first()
                .is_some_and(|entry| entry.action == "close")
        })
        .await;
    }

    #[tokio::test]
    async fn idle_shells_end() {
        let mut h = harness(ShellLimits {
            idle_timeout: Duration::from_millis(100),
            ..fast()
        });
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: None,
                reason: ExitReason::IdleTimeout
            }
        );
        assert!(shell.is_terminated());
    }

    #[tokio::test]
    async fn oversized_input_ends_the_shell() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let _shell = h.shells.recv().await.unwrap();
        socket
            .send(Message::Binary(vec![b'x'; MAX_INPUT_BYTES + 1].into()))
            .await
            .unwrap();
        assert!(matches!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                reason: ExitReason::ProtocolError,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn shells_are_limited_per_user_and_in_total() {
        let mut h = harness(ShellLimits {
            per_user: 1,
            total: 2,
            ..fast()
        });
        let alice = login(&h.host, "alice").await;
        let bob = login(&h.host, "bob").await;
        let mut first = connect(&h.path).await;
        assert!(open(&mut first, &ticket(&h.host, &alice).await).await.ok);
        let mut second = connect(&h.path).await;
        let refused = open(&mut second, &ticket(&h.host, &alice).await).await;
        assert_eq!(refused.error.unwrap().code, ErrorCode::LimitReached);
        let mut third = connect(&h.path).await;
        assert!(open(&mut third, &ticket(&h.host, &bob).await).await.ok);
        h.host.accounts.add("carol", 1003, &[]);
        h.host.passwords.set("carol", "hunter2");
        let carol = login(&h.host, "carol").await;
        let mut fourth = connect(&h.path).await;
        let refused = open(&mut fourth, &ticket(&h.host, &carol).await).await;
        assert_eq!(refused.error.unwrap().code, ErrorCode::LimitReached);

        // Closing one makes room again.
        let shell = h.shells.recv().await.unwrap();
        shell.exit(Some(0));
        drop(shell);
        exit_frame(&mut first).await;
        let server = h.server.clone();
        until(|| server.open_shells() == 1).await;
        let mut fifth = connect(&h.path).await;
        assert!(open(&mut fifth, &ticket(&h.host, &carol).await).await.ok);
    }

    #[tokio::test]
    async fn a_detached_systemd_run_ends_the_shell_and_stops_its_unit() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        // `^]` three times: systemd-run exits 0 and hangs up its terminal,
        // while the unit may run on.
        shell.exit(Some(0));
        let FakeShell {
            terminal,
            terminated,
            ..
        } = shell;
        drop(terminal);
        assert_eq!(
            exit_frame(&mut socket).await,
            ServerControl::Exit {
                status: Some(0),
                reason: ExitReason::Exited
            }
        );
        assert!(terminated.load(Ordering::SeqCst));
        let server = h.server.clone();
        until(|| server.open_shells() == 0).await;
    }

    #[tokio::test]
    async fn a_dashboard_that_stops_reading_does_not_keep_a_slot() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        let terminated = Arc::clone(&shell.terminated);
        // The shell writes until everything between it and the dashboard,
        // which reads nothing more, is full.
        let mut terminal = shell.terminal;
        let flood = tokio::spawn(async move {
            let chunk = vec![b'x'; 64 * 1024];
            while terminal.write_all(&chunk).await.is_ok() {}
        });
        let mut stalled = 0;
        while stalled < 3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            stalled = if flood.is_finished() { 0 } else { stalled + 1 };
        }
        request(&h.host, Some(&token), "session.logout", Value::Null).await;
        let server = h.server.clone();
        tokio::time::timeout(Duration::from_secs(20), async {
            while server.open_shells() != 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the shell kept its slot");
        assert!(terminated.load(Ordering::SeqCst));
        flood.abort();
        drop(socket);
    }

    #[tokio::test]
    async fn the_startup_sweep_stops_leftover_units_but_not_open_shells() {
        let mut h = harness(fast());
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        assert!(open(&mut socket, &ticket).await.ok);
        let shell = h.shells.recv().await.unwrap();
        let systemctl = pty::fake_systemctl::FakeSystemctl::new(&format!(
            "{}.service loaded active running Tetra web shell of alice\n\
             tetra-shell-1000-0123456789ab.service loaded active running Tetra web shell of alice\n",
            shell.unit
        ));
        h.server.stop_leftover_units_with(&systemctl.path()).await;
        assert_eq!(
            systemctl.calls()[1..],
            ["stop --no-block --no-ask-password -- tetra-shell-1000-0123456789ab.service"]
        );

        // Once the shell is closed its unit is a leftover too.
        shell.exit(Some(0));
        drop(shell);
        exit_frame(&mut socket).await;
        let server = h.server.clone();
        until(|| server.open_shells() == 0).await;
        assert!(h.server.inner.lock().units.is_empty());
    }

    #[tokio::test]
    async fn a_failed_start_is_an_internal_error_and_logged() {
        let h = harness(fast());
        h.spawner.fail();
        let token = login(&h.host, "alice").await;
        let ticket = ticket(&h.host, &token).await;
        let mut socket = connect(&h.path).await;
        let refused = open(&mut socket, &ticket).await;
        assert_eq!(refused.error.unwrap().code, ErrorCode::Internal);
        let entry = h.host.service.audit().recent(1, None).unwrap().remove(0);
        assert_eq!(
            (entry.module.as_str(), entry.action.as_str()),
            ("shell", "open")
        );
        assert!(!entry.ok);
        assert_eq!(h.server.open_shells(), 0);
    }
}
