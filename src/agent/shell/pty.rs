//! Starting a shell on a pseudo-terminal, behind [`PtySpawner`] so the
//! stream can be tested without root or systemd.
//!
//! [`SystemdRun`] is the real one. Tetra opens a PTY pair itself
//! (`posix_openpt` + `TIOCGPTPEER`, both close-on-exec, the master
//! non-blocking) and starts
//!
//! ```text
//! systemd-run --quiet --pty --collect --service-type=exec --send-sighup
//!     --expand-environment=no --unit=tetra-shell-<uid>-<random>
//!     --uid=<uid> -p PAMName=tetra-shell -p WorkingDirectory=-~
//!     --setenv=TERM=xterm-256color -- <login shell> -l
//! ```
//!
//! with the PTY's other end as its controlling terminal and stdio, in a new
//! session, with an empty environment apart from `PATH`, `TERM` and `LANG`.
//! systemd-run puts its own terminal in raw mode and relays it to a second
//! PTY that the transient service gets as its terminal, so the shell runs in
//! its own unit with a clean environment, as the user (never root), through
//! the `tetra-shell` PAM stack: account checks (`pam_nologin`, expiry), the
//! user's SELinux context, `loginuid`, limits, and a logind session with
//! `XDG_RUNTIME_DIR` (so `systemctl --user` and rootless Podman work).
//! Resizing the outer PTY (`TIOCSWINSZ`) sends systemd-run `SIGWINCH`, and it
//! resizes the inner one.
//!
//! [`ShellProcess::terminate`] stops the unit (`SIGTERM` then `SIGHUP` to
//! everything in it, `SIGKILL` after `TimeoutStopSec`), whether or not
//! systemd-run is still running, hangs up systemd-run and reaps it.

use std::{
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};

use super::frames::WindowSize;
use crate::auth::shell::ShellGrant;

/// PAM service of web shells (`pam/tetra-shell`, installed in `/etc/pam.d`).
pub const DEFAULT_PAM_SERVICE: &str = "tetra-shell";
/// `TERM` of web shells: what xterm.js emulates.
pub const TERM: &str = "xterm-256color";
/// How long `systemctl stop` may take before Tetra stops waiting for it.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(15);
/// How long systemd-run gets to exit after the hangup before it is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(5);

/// What to start.
#[derive(Debug, Clone, Copy)]
pub struct ShellRequest<'a> {
    pub grant: &'a ShellGrant,
    /// Transient unit name, without `.service`.
    pub unit: &'a str,
    pub size: WindowSize,
}

/// The terminal side Tetra reads and writes.
pub trait PtyIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> PtyIo for T {}

/// Changes the terminal's size.
pub trait Resize: Send + Sync {
    /// # Errors
    /// Fails when the terminal is gone.
    fn resize(&self, size: WindowSize) -> Result<()>;
}

/// The process behind a shell.
pub trait ShellProcess: Send {
    /// Wait for it to exit: its exit status, or `None` when a signal ended
    /// it. Cancel-safe, so it can be polled in a `select!` loop.
    fn wait(&mut self) -> BoxFuture<'_, Result<Option<i32>>>;

    /// End the shell, whether or not it has exited, and reap it. Called
    /// once, at the end.
    fn terminate(&mut self) -> BoxFuture<'_, ()>;
}

/// A started shell.
pub struct SpawnedShell {
    pub io: Box<dyn PtyIo>,
    pub resizer: Box<dyn Resize>,
    pub process: Box<dyn ShellProcess>,
}

/// Starts shells.
pub trait PtySpawner: Send + Sync {
    /// Start the login shell of `request.grant` as that user.
    ///
    /// # Errors
    /// Fails when the PTY or the process cannot be created.
    fn spawn(&self, request: &ShellRequest<'_>) -> Result<SpawnedShell>;
}

/// [`PtySpawner`] that runs `systemd-run --pty`. See the module docs.
#[derive(Debug, Clone)]
pub struct SystemdRun {
    pub pam_service: String,
    pub systemd_run: PathBuf,
    pub systemctl: PathBuf,
}

impl SystemdRun {
    #[must_use]
    pub fn new(pam_service: String) -> Self {
        Self {
            pam_service,
            systemd_run: "/usr/bin/systemd-run".into(),
            systemctl: "/usr/bin/systemctl".into(),
        }
    }

    /// systemd-run's arguments for `request`.
    ///
    /// # Errors
    /// Refuses root and shells that are not absolute paths.
    pub fn arguments(&self, request: &ShellRequest<'_>) -> Result<Vec<String>> {
        let grant = request.grant;
        ensure!(grant.uid != 0, "refusing to start a web shell as root");
        ensure!(
            grant.shell.starts_with('/'),
            "the login shell of `{}` is not an absolute path",
            grant.username
        );
        ensure!(
            !self.pam_service.is_empty()
                && self
                    .pam_service
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
            "invalid PAM service name"
        );
        Ok(vec![
            "--quiet".into(),
            "--pty".into(),
            "--collect".into(),
            "--service-type=exec".into(),
            "--send-sighup".into(),
            "--expand-environment=no".into(),
            format!("--unit={}", request.unit),
            format!("--description=Tetra web shell of {}", grant.username),
            // Numeric, so the account cannot be swapped by name in between.
            // Groups (primary and supplementary) come from the account.
            format!("--uid={}", grant.uid),
            "--property".into(),
            format!("PAMName={}", self.pam_service),
            // `~` is the user's home; `-` starts in `/` if it is missing.
            "--property".into(),
            "WorkingDirectory=-~".into(),
            "--property".into(),
            "TimeoutStopSec=10s".into(),
            format!("--setenv=TERM={TERM}"),
            "--".into(),
            grant.shell.clone(),
            "-l".into(),
        ])
    }
}

impl PtySpawner for SystemdRun {
    fn spawn(&self, request: &ShellRequest<'_>) -> Result<SpawnedShell> {
        let arguments = self.arguments(request)?;
        let (io, resizer, child) = start(&self.systemd_run, &arguments, request.size)?;
        Ok(SpawnedShell {
            io: Box::new(io),
            resizer: Box::new(resizer),
            process: Box::new(SystemdRunProcess {
                child,
                unit: format!("{}.service", request.unit),
                systemctl: self.systemctl.clone(),
            }),
        })
    }
}

/// Run `program` on a new PTY of `size`, as the leader of a new session
/// with the PTY as its controlling terminal and stdio, and an empty
/// environment apart from `PATH`, `TERM` and `LANG`.
fn start(
    program: &Path,
    arguments: &[String],
    size: WindowSize,
) -> Result<(PtyMaster, MasterResizer, tokio::process::Child)> {
    let (master, terminal) = open_pty(size)?;
    let mut command = tokio::process::Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/usr/sbin")
        .env("TERM", TERM)
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(Stdio::from(terminal.try_clone()?))
        .stdout(Stdio::from(terminal.try_clone()?))
        .stderr(Stdio::from(terminal))
        .kill_on_drop(true);
    // SAFETY: the closure runs in the forked child before exec and only
    // makes async-signal-safe system calls (setsid, ioctl) on its own
    // stdin, which std has already pointed at the terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    };
    let child = command
        .spawn()
        .with_context(|| format!("failed to start `{}`", program.display()))?;
    // The command holds Tetra's copies of the terminal: drop them, so the
    // master sees a hangup once the child and its children are gone.
    drop(command);
    let master = Arc::new(master);
    Ok((
        PtyMaster::new(Arc::clone(&master))?,
        MasterResizer(master),
        child,
    ))
}

/// A new PTY pair of `size`: the master (non-blocking) and the terminal.
/// Both are close-on-exec, so no other child inherits them.
fn open_pty(size: WindowSize) -> Result<(OwnedFd, OwnedFd)> {
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: posix_openpt only opens /dev/ptmx; the result is checked.
    let master = unsafe { libc::posix_openpt(flags | libc::O_NONBLOCK) };
    let master = owned(master).context("failed to open a PTY")?;
    // SAFETY: `master` is an open PTY master owned by this function.
    if unsafe { libc::unlockpt(master.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error()).context("failed to unlock the PTY");
    }
    // TIOCGPTPEER opens the matching terminal without a path lookup.
    // SAFETY: `master` is an open PTY master; the ioctl takes open flags
    // and returns a new descriptor, which is checked.
    let terminal = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTPEER, flags) };
    let terminal = owned(terminal).context("failed to open the PTY's terminal")?;
    set_size(master.as_fd().as_raw_fd(), size)?;
    Ok((master, terminal))
}

/// Take ownership of a descriptor a system call returned.
fn owned(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-negative return value is a new descriptor nothing else
    // owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_size(fd: RawFd, size: WindowSize) -> Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `fd` is an open PTY descriptor and `winsize` outlives the call.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &raw const winsize) } < 0 {
        return Err(io::Error::last_os_error()).context("failed to resize the PTY");
    }
    Ok(())
}

struct MasterResizer(Arc<OwnedFd>);

impl Resize for MasterResizer {
    fn resize(&self, size: WindowSize) -> Result<()> {
        set_size(self.0.as_raw_fd(), size)
    }
}

/// The non-blocking PTY master as an async stream. Reading ends (`Ok(0)`)
/// once nothing holds the terminal open any more (`EIO`).
struct PtyMaster(AsyncFd<Arc<OwnedFd>>);

impl PtyMaster {
    fn new(master: Arc<OwnedFd>) -> io::Result<Self> {
        // SAFETY: the `Arc` keeps the descriptor open, and refers to the same
        // descriptor, for as long as the `AsyncFd` holds it.
        unsafe { AsyncFd::register(master) }
            .map(Self)
            .map_err(|error| error.into_parts().1)
    }
}

impl AsyncRead for PtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| {
                nix::unistd::read(fd.get_ref().as_fd(), unfilled).map_err(io::Error::from)
            }) {
                Ok(Ok(read)) => {
                    buf.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for PtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard
                .try_io(|fd| nix::unistd::write(fd.get_ref().as_fd(), buf).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct SystemdRunProcess {
    child: tokio::process::Child,
    unit: String,
    systemctl: PathBuf,
}

impl ShellProcess for SystemdRunProcess {
    fn wait(&mut self) -> BoxFuture<'_, Result<Option<i32>>> {
        Box::pin(async move { Ok(self.child.wait().await?.code()) })
    }

    fn terminate(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // Always, even when systemd-run has exited: it also exits while
            // its unit runs on, when the user detaches it (`^]` three times)
            // or when it is hung up, and a shell that ignores `SIGHUP` would
            // then outlive whatever ended it (logout, revocation, a lock,
            // the idle timeout or the maximum lifetime).
            stop_units(&self.systemctl, std::slice::from_ref(&self.unit)).await;
            if matches!(self.child.try_wait(), Ok(None))
                && let Some(pid) = self.child.id().and_then(|pid| i32::try_from(pid).ok())
            {
                // Its own session and process group (setsid).
                nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGHUP,
                )
                .ok();
            }
            if tokio::time::timeout(HANGUP_GRACE, self.child.wait())
                .await
                .is_err()
            {
                self.child.start_kill().ok();
            }
            // Reap it, so no zombie is left behind.
            self.child.wait().await.ok();
        })
    }
}

/// `systemctl stop --no-block <units>`: `SIGTERM` and `SIGHUP` to every
/// process of the units, `SIGKILL` after `TimeoutStopSec`. Failures are
/// logged.
async fn stop_units(systemctl: &Path, units: &[String]) {
    let mut command = systemctl_command(systemctl);
    command
        .args(["stop", "--no-block", "--no-ask-password", "--"])
        .args(units)
        .stdout(Stdio::null());
    let units = units.join(" ");
    match tokio::time::timeout(SYSTEMCTL_TIMEOUT, command.status()).await {
        Ok(Ok(status)) if status.success() => {}
        // 5: a unit is already gone.
        Ok(Ok(status)) if status.code() == Some(5) => {}
        Ok(Ok(status)) => eprintln!("`systemctl stop {units}` failed: {status}"),
        Ok(Err(error)) => eprintln!("failed to run `systemctl stop {units}`: {error}"),
        Err(_) => eprintln!("`systemctl stop {units}` timed out"),
    }
}

/// `systemctl` with a minimal environment and no stdin or stderr, killed if
/// Tetra stops waiting for it.
fn systemctl_command(systemctl: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(systemctl);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

#[cfg(any(test, feature = "testing"))]
pub use fake::{FakeShell, FakeSpawner};

#[cfg(any(test, feature = "testing"))]
mod fake {
    //! A [`PtySpawner`] whose shells the test drives.
    #![allow(clippy::missing_panics_doc, clippy::unwrap_in_result)]

    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::{
        io::DuplexStream,
        sync::{mpsc, watch},
    };

    use super::{
        Arc, BoxFuture, PtySpawner, Resize, Result, ShellGrant, ShellProcess, ShellRequest,
        SpawnedShell, WindowSize,
    };

    /// Bytes buffered in each direction of a fake terminal.
    const BUFFER: usize = 64 * 1024;

    /// Hands every shell it "starts" to the test.
    #[derive(Debug)]
    pub struct FakeSpawner {
        shells: mpsc::UnboundedSender<FakeShell>,
        fail: AtomicBool,
    }

    impl FakeSpawner {
        /// The spawner and where its shells arrive.
        #[must_use]
        pub fn new() -> (Self, mpsc::UnboundedReceiver<FakeShell>) {
            let (shells, receiver) = mpsc::unbounded_channel();
            (
                Self {
                    shells,
                    fail: AtomicBool::new(false),
                },
                receiver,
            )
        }

        /// Make every spawn fail from now on.
        pub fn fail(&self) {
            self.fail.store(true, Ordering::SeqCst);
        }
    }

    /// One fake shell: the terminal's far end, and what Tetra did to it.
    #[derive(Debug)]
    pub struct FakeShell {
        pub grant: ShellGrant,
        pub unit: String,
        pub size: WindowSize,
        /// Bytes Tetra writes arrive here; bytes written here reach Tetra.
        /// Dropping it hangs up the terminal.
        pub terminal: DuplexStream,
        pub resizes: Arc<Mutex<Vec<WindowSize>>>,
        pub terminated: Arc<AtomicBool>,
        exit: watch::Sender<Status>,
    }

    impl FakeShell {
        /// Make the process exit with `status`.
        pub fn exit(&self, status: Option<i32>) {
            self.exit.send_replace(Status::Exited(status));
        }

        #[must_use]
        pub fn is_terminated(&self) -> bool {
            self.terminated.load(Ordering::SeqCst)
        }
    }

    struct FakeResizer(Arc<Mutex<Vec<WindowSize>>>);

    impl Resize for FakeResizer {
        fn resize(&self, size: WindowSize) -> Result<()> {
            self.0.lock().unwrap().push(size);
            Ok(())
        }
    }

    /// A fake process's state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Status {
        Running,
        /// With its exit status, or `None` when a signal ended it.
        Exited(Option<i32>),
    }

    /// Kill a running fake process; whether it was running.
    fn hang_up(status: &mut Status) -> bool {
        let running = *status == Status::Running;
        if running {
            *status = Status::Exited(None);
        }
        running
    }

    struct FakeProcess {
        exit: watch::Receiver<Status>,
        sender: watch::Sender<Status>,
        terminated: Arc<AtomicBool>,
    }

    impl ShellProcess for FakeProcess {
        fn wait(&mut self) -> BoxFuture<'_, Result<Option<i32>>> {
            Box::pin(async move {
                let status = *self
                    .exit
                    .wait_for(|status| *status != Status::Running)
                    .await?;
                Ok(match status {
                    Status::Running | Status::Exited(None) => None,
                    Status::Exited(code) => code,
                })
            })
        }

        fn terminate(&mut self) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                self.terminated.store(true, Ordering::SeqCst);
                self.sender.send_if_modified(hang_up);
            })
        }
    }

    impl PtySpawner for FakeSpawner {
        fn spawn(&self, request: &ShellRequest<'_>) -> Result<SpawnedShell> {
            anyhow::ensure!(!self.fail.load(Ordering::SeqCst), "spawning failed");
            let (tetra, terminal) = tokio::io::duplex(BUFFER);
            let resizes = Arc::new(Mutex::new(Vec::new()));
            let terminated = Arc::new(AtomicBool::new(false));
            let (exit, receiver) = watch::channel(Status::Running);
            let process = FakeProcess {
                exit: receiver,
                sender: exit.clone(),
                terminated: Arc::clone(&terminated),
            };
            self.shells
                .send(FakeShell {
                    grant: request.grant.clone(),
                    unit: request.unit.to_owned(),
                    size: request.size,
                    terminal,
                    resizes: Arc::clone(&resizes),
                    terminated,
                    exit,
                })
                .ok();
            Ok(SpawnedShell {
                io: Box::new(tetra),
                resizer: Box::new(FakeResizer(resizes)),
                process: Box::new(process),
            })
        }
    }
}

#[cfg(test)]
pub(super) mod fake_systemctl {
    //! A `systemctl` for tests.
    use std::{path::PathBuf, time::Duration};

    /// A `systemctl` that logs its arguments and lists `listing`.
    pub struct FakeSystemctl {
        dir: tempfile::TempDir,
    }

    impl FakeSystemctl {
        pub fn new(listing: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("log");
            let list = dir.path().join("listing");
            std::fs::write(&list, listing).unwrap();
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
                 if [ \"$1\" = list-units ]; then cat '{}'; fi\n",
                log.display(),
                list.display()
            );
            let path = dir.path().join("systemctl");
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let fake = Self { dir };
            // Another test's fork may briefly hold the script open for
            // writing (ETXTBSY); once it runs, nothing can any more.
            for _ in 0..100 {
                match std::process::Command::new(&path).arg("probe").status() {
                    Ok(_) => {
                        std::fs::remove_file(&log).ok();
                        return fake;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            panic!("the fake systemctl stayed busy");
        }

        pub fn path(&self) -> PathBuf {
            self.dir.path().join("systemctl")
        }

        pub fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fake_systemctl::FakeSystemctl, *};
    use crate::auth::sessions::ClientKind;

    fn grant(uid: u32, shell: &str) -> ShellGrant {
        ShellGrant {
            client: ClientKind::Dashboard,
            session_id: "s".into(),
            uid,
            username: "alice".into(),
            shell: shell.into(),
        }
    }

    #[test]
    fn systemd_run_runs_the_login_shell_as_the_user() {
        let spawner = SystemdRun::new(DEFAULT_PAM_SERVICE.into());
        let grant = grant(1000, "/bin/bash");
        let request = ShellRequest {
            grant: &grant,
            unit: "tetra-shell-1000-abc",
            size: WindowSize { cols: 80, rows: 24 },
        };
        let arguments = spawner.arguments(&request).unwrap();
        for expected in [
            "--pty",
            "--uid=1000",
            "PAMName=tetra-shell",
            "WorkingDirectory=-~",
            "--unit=tetra-shell-1000-abc",
            "--expand-environment=no",
            "--send-sighup",
            "--setenv=TERM=xterm-256color",
        ] {
            assert!(arguments.iter().any(|a| a == expected), "{expected}");
        }
        assert_eq!(arguments[arguments.len() - 3..], ["--", "/bin/bash", "-l"]);
    }

    #[test]
    fn systemd_run_refuses_root_and_odd_shells() {
        let spawner = SystemdRun::new(DEFAULT_PAM_SERVICE.into());
        for grant in [grant(0, "/bin/bash"), grant(1000, "bash")] {
            let request = ShellRequest {
                grant: &grant,
                unit: "u",
                size: WindowSize { cols: 80, rows: 24 },
            };
            spawner.arguments(&request).unwrap_err();
        }
        let bad = SystemdRun::new("login\nauth".into());
        let grant = grant(1000, "/bin/bash");
        let request = ShellRequest {
            grant: &grant,
            unit: "u",
            size: WindowSize { cols: 80, rows: 24 },
        };
        bad.arguments(&request).unwrap_err();
    }

    #[test]
    fn ptys_are_close_on_exec_and_sized() {
        let (master, terminal) = open_pty(WindowSize {
            cols: 132,
            rows: 43,
        })
        .unwrap();
        for fd in [&master, &terminal] {
            let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        let mut winsize = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `terminal` is open and `winsize` outlives the call.
        let result =
            unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCGWINSZ, &raw mut winsize) };
        assert_eq!(result, 0);
        assert_eq!((winsize.ws_col, winsize.ws_row), (132, 43));
    }

    #[tokio::test]
    async fn the_master_reads_what_the_terminal_writes_and_ends_on_hangup() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (master, terminal) = open_pty(WindowSize { cols: 80, rows: 24 }).unwrap();
        let mut master = PtyMaster::new(Arc::new(master)).unwrap();
        // Raw mode, so bytes pass unchanged.
        let mut termios = nix::sys::termios::tcgetattr(&terminal).unwrap();
        nix::sys::termios::cfmakeraw(&mut termios);
        nix::sys::termios::tcsetattr(&terminal, nix::sys::termios::SetArg::TCSANOW, &termios)
            .unwrap();
        nix::unistd::write(&terminal, b"hello").unwrap();
        let mut buf = [0_u8; 5];
        master.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        master.write_all(b"typed").await.unwrap();
        let mut typed = [0_u8; 5];
        nix::unistd::read(&terminal, &mut typed).unwrap();
        assert_eq!(&typed, b"typed");
        drop(terminal);
        assert_eq!(master.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn programs_start_on_their_own_controlling_terminal() {
        use tokio::io::AsyncReadExt;
        // Field 6 of /proc/<pid>/stat is the session.
        let script = "stty size; set -- $(cat /proc/$$/stat); \
                      test -t 0 && test \"$6\" = $$ && echo leader; \
                      echo env=$(env | grep -c .); exit 7";
        let (mut io, resizer, mut child) = start(
            Path::new("/bin/sh"),
            &["-c".into(), script.into()],
            WindowSize { cols: 90, rows: 33 },
        )
        .unwrap();
        resizer.resize(WindowSize { cols: 91, rows: 34 }).ok();
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), io.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("leader"), "{output}");
        assert!(
            output.contains("33 90") || output.contains("34 91"),
            "{output}"
        );
        // PATH, TERM, LANG, and what sh adds itself (PWD, SHLVL, _).
        let count: usize = output
            .split("env=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|count| count.parse().ok())
            .unwrap();
        assert!(count <= 6, "{output}");
        assert_eq!(child.wait().await.unwrap().code(), Some(7));
    }

    fn process(child: tokio::process::Child, systemctl: &FakeSystemctl) -> SystemdRunProcess {
        SystemdRunProcess {
            child,
            unit: "tetra-shell-1000-abc.service".into(),
            systemctl: systemctl.path(),
        }
    }

    #[tokio::test]
    async fn terminate_stops_the_unit_after_systemd_run_exited() {
        // systemd-run exits 0 when the user detaches it, while the unit runs on.
        let systemctl = FakeSystemctl::new("");
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let mut process = process(child, &systemctl);
        assert_eq!(process.wait().await.unwrap(), Some(0));
        process.terminate().await;
        assert_eq!(
            systemctl.calls(),
            ["stop --no-block --no-ask-password -- tetra-shell-1000-abc.service"]
        );
    }

    #[tokio::test]
    async fn terminate_stops_the_unit_and_hangs_up_a_running_systemd_run() {
        let systemctl = FakeSystemctl::new("");
        let (_io, _resizer, child) = start(
            Path::new("/bin/sh"),
            &["-c".into(), "sleep 60".into()],
            WindowSize { cols: 80, rows: 24 },
        )
        .unwrap();
        let mut process = process(child, &systemctl);
        tokio::time::timeout(HANGUP_GRACE, process.terminate())
            .await
            .expect("the hangup did not end it");
        assert!(matches!(process.child.try_wait(), Ok(Some(status)) if status.code().is_none()));
        assert_eq!(
            systemctl.calls(),
            ["stop --no-block --no-ask-password -- tetra-shell-1000-abc.service"]
        );
    }

    /// Starts a real shell through systemd. Needs root and a user to run it
    /// as: `sudo TETRA_TEST_SHELL_USER=alice cargo test -- --ignored real`.
    #[tokio::test]
    #[ignore = "needs root, systemd and the tetra-shell PAM service"]
    async fn real_systemd_shell_runs_as_the_user() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let name = std::env::var("TETRA_TEST_SHELL_USER").unwrap();
        let user = nix::unistd::User::from_name(&name).unwrap().unwrap();
        let grant = ShellGrant {
            client: ClientKind::Dashboard,
            session_id: "test".into(),
            uid: user.uid.as_raw(),
            username: name,
            shell: user.shell.to_string_lossy().into_owned(),
        };
        let pam = std::env::var("TETRA_TEST_SHELL_PAM").unwrap_or_else(|_| "login".into());
        let spawner = SystemdRun::new(pam);
        let unit = format!("tetra-shell-test-{}", std::process::id());
        let mut shell = spawner
            .spawn(&ShellRequest {
                grant: &grant,
                unit: &unit,
                size: WindowSize { cols: 80, rows: 24 },
            })
            .unwrap();
        shell
            .io
            .write_all(b"echo uid=$(id -u) term=$TERM; exit 3\n")
            .await
            .unwrap();
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), shell.io.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains(&format!("uid={} term={TERM}", grant.uid)),
            "{output}"
        );
        assert_eq!(shell.process.wait().await.unwrap(), Some(3));
        shell.process.terminate().await;
    }
}
