//! Host commands the auth service runs itself (Caddy reloads, the dashboard
//! and OOBE units, the setup handoff timer), behind a trait so tests can
//! record them instead.
//!
//! Arguments must never contain a credential: a failing command's line ends
//! up in error messages, logs and the action log.

use crate::prelude::*;

/// Runs host commands as root.
pub trait HostControl: Send + Sync {
    /// Run `program` with `args` and wait for it.
    ///
    /// # Errors
    /// Fails when the command cannot start or exits unsuccessfully.
    fn run(&self, program: &str, args: &[&str]) -> Result<()>;

    /// `systemctl <args>`.
    ///
    /// # Errors
    /// See [`Self::run`].
    fn systemctl(&self, args: &[&str]) -> Result<()> {
        self.run("systemctl", args)
    }
}

/// [`HostControl`] that runs real commands.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemHost;

impl HostControl for SystemHost {
    fn run(&self, program: &str, args: &[&str]) -> Result<()> {
        crate::agent::module_support::run_command_output_as(program, args, false, None).map(drop)
    }
}
