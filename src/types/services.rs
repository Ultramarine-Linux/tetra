//! `services` module payloads, and the scope a service lives in.

use crate::prelude::*;

use super::default_log_lines;

/// Which service manager a `services` action talks to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceScope {
    /// The system manager.
    #[default]
    System,
    /// The user manager of whoever the command runs as (`systemctl --user`).
    User,
    /// The user manager of the `ultramarine-apps` account that user apps run
    /// under (`systemctl --user -M ultramarine-apps@`).
    Apps,
}

impl ServiceScope {
    /// `args` for `systemctl` in this scope, run as root (or as anyone, for
    /// `system` and `user`).
    #[must_use]
    pub fn command_args<const N: usize>(self, args: [&str; N]) -> Vec<&str> {
        self.command_args_as(args, false)
    }

    /// `args` for `systemctl` in this scope. In `apps` scope, a command run
    /// as the apps account itself (`as_apps`) reaches its manager with
    /// `--user`; root needs `-M ultramarine-apps@`.
    #[must_use]
    pub fn command_args_as<const N: usize>(self, args: [&str; N], as_apps: bool) -> Vec<&str> {
        let prefix: &[&str] = match self {
            Self::System => &[],
            Self::User => &["--user"],
            Self::Apps if as_apps => &["--user"],
            Self::Apps => &[
                "--user",
                "-M",
                crate::agent::apps_account::SYSTEMCTL_MACHINE,
            ],
        };
        let mut scoped = Vec::with_capacity(args.len().saturating_add(prefix.len()));
        scoped.extend_from_slice(prefix);
        scoped.extend(args);
        scoped
    }
}

#[derive(Debug, Deserialize)]
pub struct ServiceRequest {
    pub service: String,
    #[serde(default)]
    pub scope: ServiceScope,
    #[serde(default)]
    pub dry_run: bool,
}

/// Payload for `services.list`; all fields are optional so `{}` lists system
/// services as before.
#[derive(Debug, Deserialize)]
pub struct ServiceListRequest {
    #[serde(default)]
    pub scope: ServiceScope,
}

#[derive(Debug, Deserialize)]
pub struct ServiceLogsRequest {
    pub service: String,
    #[serde(default)]
    pub scope: ServiceScope,
    #[serde(default = "default_log_lines")]
    pub lines: u16,
}

#[derive(Debug, Deserialize)]
pub struct DaemonReloadRequest {
    #[serde(default)]
    pub scope: ServiceScope,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ServiceStatus {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

impl ServiceStatus {
    #[must_use]
    pub fn parse_all(stdout: &str) -> Vec<Self> {
        stdout.lines().filter_map(Self::parse).collect()
    }

    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let unit = fields.next()?;
        let load = fields.next()?;
        let active = fields.next()?;
        let sub = fields.next()?;
        Some(Self {
            unit: unit.to_owned(),
            load: load.to_owned(),
            active: active.to_owned(),
            sub: sub.to_owned(),
            description: fields.collect::<Vec<_>>().join(" "),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn service_requests_default_and_apply_scope_consistently() {
        let logs: ServiceLogsRequest =
            serde_json::from_value(json!({ "service": "sshd" })).unwrap();
        assert_eq!(logs.lines, 100);
        assert_eq!(
            logs.scope.command_args(["status", "sshd"]),
            ["status", "sshd"]
        );
        assert_eq!(
            ServiceScope::User.command_args(["status", "sshd"]),
            ["--user", "status", "sshd"]
        );
        assert_eq!(
            ServiceScope::Apps.command_args(["start", "app.service"]),
            ["--user", "-M", "ultramarine-apps@", "start", "app.service"]
        );
        assert_eq!(
            ServiceScope::Apps.command_args_as(["status", "app.service"], true),
            ["--user", "status", "app.service"]
        );
    }

    #[test]
    fn service_status_parser_skips_malformed_rows_and_preserves_description() {
        let statuses = ServiceStatus::parse_all(
            "invalid\nsshd.service loaded active running OpenSSH server daemon\n",
        );
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].unit, "sshd.service");
        assert_eq!(statuses[0].description, "OpenSSH server daemon");
    }
}
