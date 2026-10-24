//! systemd service inspection and control via `systemctl` / `journalctl`.
//!
//! The services module is the control plane's window into the host's service
//! manager. Read actions (`list`, `status`, `logs`) run unconditionally;//! mutating actions (`start`/`stop`/`restart`/`enable`/`disable` and
//! `daemon_reload`) honor the shared `dry_run` flag so a controller can preview
//! the exact `systemctl` invocation before applying it.
//!
//! Both system and per-user systemd scopes are supported: a `scope` field on
//! the payload selects which, and is translated into the `--user` flag (or its
//! absence) on every `systemctl`/`journalctl` invocation. `list` additionally
//! parses the raw `list-units` table into a stable `services` array.

use crate::agent::module_support::parse_payload;
use crate::prelude::*;

use crate::types::{DaemonReloadRequest, ServiceListRequest, ServiceLogsRequest, ServiceRequest};

/// Marker type for the services module. Stateless; all behavior lives in the
/// [`Mod`] impl and the static [`INFO`] descriptor.
#[derive(Clone, Copy, Debug)]
pub struct ServicesModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "services",
    feature: "services",
    description: "Inspect and control systemd services, including logs and enablement state.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "list",
        "status",
        "logs",
        "daemon_reload",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
    ],
    privileged_actions: &[
        "daemon_reload",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
    ],
};

impl Mod for ServicesModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        // Delegate `capabilities`/`plan` to the module descriptor first.
        if let Some(response) = INFO.metadata_response(action, &payload) {
            return Ok(response);
        }

        // The five single-service mutations share one arm because their
        // `systemctl` invocation has identical shape: `systemctl <action>
        // <service>`. The `action` string is already a valid systemctl
        // subcommand, which is why it can be forwarded directly.

        if ["start", "stop", "restart", "enable", "disable"].contains(&action) {
            let payload: ServiceRequest = parse_payload(payload)?;
            let args = payload.scope.command_args([action, &payload.service]);
            return crate::cmd!((payload.dry_run) { &INFO, action, user } "systemctl" => &args ; json);
        }

        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    List: ServiceListRequest => {
        // `list-units` is a read, so it is never dry-run. The flags below
        // ask systemctl for machine-friendly output: `--plain` disables
        // column alignment/headers, `--legend=false` drops the summary
        // footer, and `--no-pager` avoids interactive pagers. We still
        // return the raw stdout alongside the parsed `services` array so a
        // controller can fall back to the verbatim table if needed.
        let args = payload.scope.command_args([
            "--no-pager",
            "--plain",
            "--legend=false",
            "list-units",
            "--type=service",
            "--all",
        ]);
        let result = crate::cmd!({ &INFO, "list", user } "systemctl" => &args)?;
        Ok(jsonf! {
            "command": result.command,
            "status": result.status,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "dry_run": result.dry_run,
            "services": parse_systemctl_services(&result.stdout),
        })
    },
    Status: ServiceRequest => {
        let args = payload.scope.command_args([
            "--no-pager",
            "--plain",
            "status",
            &payload.service,
        ]);
        crate::cmd!({ &INFO, "status", user } "systemctl" => &args ; json)
    },
    Logs: ServiceLogsRequest => {
        // `journalctl -u <unit>` follows the unit's journal across
        // whatever files it spans; `-n` caps the tail to keep payloads
        // bounded. `logs` is a read and therefore never dry-run.
        let lines = payload.lines.to_string();
        let args = payload.scope.command_args([
            "--no-pager",
            "-u",
            &payload.service,
            "-n",
            &lines,
        ]);
        crate::cmd!({ &INFO, "logs", user } "journalctl" => &args ; json)
    },
    DaemonReload: DaemonReloadRequest => {
        let args = payload.scope.command_args(["daemon-reload"]);
        crate::cmd!((payload.dry_run) { &INFO, "daemon_reload", user } "systemctl" => &args ; json)
    },
});

/// Parses the whitespace-separated rows emitted by `systemctl list-units`.
///
/// Each row has the fixed prefix `UNIT LOAD ACTIVE SUB` followed by a
/// free-form `DESCRIPTION` that may contain spaces. We split on runs of
/// whitespace and treat the first four fields as the fixed columns, rejoining
/// everything from index 4 onward as the description. Rows with fewer than
/// four fields (e.g. stray blank lines or the suppressed legend) are dropped
/// via the `>= 4` guard.
fn parse_systemctl_services(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let (unit, load, active, sub) = it.next_tuple()?;
            Some(jsonf! {
                unit,
                load,
                active,
                sub,
                "description": it.join(" "),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ServiceScope, ServiceStatus};

    #[test]
    fn parses_systemctl_service_rows() {
        let services =
            ServiceStatus::parse_all("sshd.service loaded active running OpenSSH server daemon\n");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].unit, "sshd.service");
        assert_eq!(services[0].description, "OpenSSH server daemon");
    }

    #[test]
    fn dry_run_start_does_not_call_systemctl() {
        let response = ServicesModule
            .handle(
                "start",
                jsonf! {
                    "service": "sshd.service",
                    "scope": ServiceScope::System,
                    "dry_run": true,
                },
                None,
            )
            .unwrap();

        assert_eq!(response["command"], "systemctl start sshd.service");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }

    #[test]
    fn daemon_reload_supports_dry_run() {
        let response = DaemonReload(DaemonReloadRequest {
            scope: ServiceScope::System,
            dry_run: true,
        })
        .handle(None)
        .unwrap();

        assert_eq!(response["command"], "systemctl daemon-reload");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }

    #[test]
    fn user_scope_adds_systemctl_user_flag() {
        let response = ServicesModule
            .handle(
                "start",
                jsonf! {
                    "service": "tetra-demo.service",
                    "scope": ServiceScope::User,
                    "dry_run": true,
                },
                None,
            )
            .unwrap();

        assert_eq!(
            response["command"],
            "systemctl --user start tetra-demo.service"
        );
    }

    #[test]
    fn list_action_defaults_to_system_scope() {
        let payload: ServiceListRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(payload.scope, ServiceScope::System);
    }

    #[test]
    fn list_action_accepts_user_scope() {
        let payload: ServiceListRequest = serde_json::from_str(r#"{"scope": "user"}"#).unwrap();
        assert_eq!(payload.scope, ServiceScope::User);
    }
}
