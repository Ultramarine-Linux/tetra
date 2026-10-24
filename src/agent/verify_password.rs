//! Password verification for headless elevation.
//!
//! On a headless server, the dashboard must provide the administrator password
//! directly. Tetra verifies it against the host's shadow database without
//! retaining the plaintext.

use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Verify a password for `username` using the host's shadow database.
///
/// This uses `/usr/sbin/unix_chkpwd` when available (part of Linux-PAM and
/// present on Fedora/RHEL systems). Since Tetra runs as root it can invoke
/// the helper directly.
///
/// Returns `true` when the password is correct, `false` otherwise.
///
/// # Errors
/// Errors only on spawn failure or missing helper.
pub fn verify_password(username: &str, password: &str) -> Result<bool> {
    if username.is_empty() || password.is_empty() {
        bail!("username and password must be non-empty");
    }

    let helper = if std::path::Path::new("/usr/sbin/unix_chkpwd").exists() {
        "/usr/sbin/unix_chkpwd"
    } else {
        "/sbin/unix_chkpwd"
    };

    // unix_chkpwd rejects direct invocation by root. Run it as the account being
    // verified so PAM sees the expected real UID; Tetra itself remains root for
    // the privileged operation that follows elevation.
    let mut child = Command::new("runuser")
        .args(["-u", username, "--", helper, username, "nullok"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn runuser for password verification")?;

    let mut stdin = child.stdin.take().context("no stdin")?;
    stdin.write_all(password.as_bytes())?;
    stdin.write_all(b"\n")?;
    drop(stdin);
    // A ten-second deadline is bounded well below Instant's representable range.
    #[allow(clippy::arithmetic_side_effects)]
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().context("unix_chkpwd exited abnormally")? {
            if status.success() {
                return Ok(true);
            }
            let stderr = child
                .stderr
                .take()
                .map(|mut stream| {
                    let mut text = String::new();
                    std::io::Read::read_to_string(&mut stream, &mut text).ok();
                    text
                })
                .unwrap_or_default();
            bail!(
                "password verification helper failed with status {:?}: {}",
                status.code(),
                stderr.trim()
            );
        }
        if Instant::now() >= deadline {
            let _kill_result: std::io::Result<()> = child.kill();
            let _wait_result: std::io::Result<std::process::ExitStatus> = child.wait();
            bail!("password verification timed out after 10 seconds");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
