//! systemd service inspection and control via `systemctl` / `journalctl`.
//!
//! The services module is the control plane's window into the host's service
//! manager. Read actions (`list`, `status`, `logs`) run unconditionally;//! mutating actions (`start`/`stop`/`restart`/`enable`/`disable` and
//! `daemon_reload`) honor the shared `dry_run` flag so a controller can preview
//! the exact `systemctl` invocation before applying it.
//!
//! A `scope` field on the payload selects the manager: `system` (the
//! default), `user` (`--user`, the manager of whoever the command runs as) or
//! `apps`, the user manager of the `ultramarine-apps` account that user apps
//! run under (`--user -M ultramarine-apps@` as root, plain `--user` when the
//! command runs as that account). `list` additionally parses the raw
//! `list-units` table into a stable `services` array.

use serde_json::json;

use crate::actions;
use crate::agent::apps_account::{APPS_USER, AppsAccount};
use crate::agent::module_support::{ModuleInfo, ModuleStatus, positional, run_for};
use crate::agent::modules::Mod;
use crate::prelude::*;

use crate::types::{
    DaemonReloadRequest, ServiceListRequest, ServiceLogsRequest, ServiceRequest, ServiceScope,
    ServiceStatus,
};

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
        let args = payload.scope.command_args_as([
            "--no-pager",
            "--plain",
            "--legend=false",
            "list-units",
            "--type=service",
            "--all",
        ], as_apps("list", user));
        let result = run_for(&INFO, "list", user, "systemctl", &args, false)?;
        Ok(json!({
            "command": result.command,
            "status": result.status,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "dry_run": result.dry_run,
            "services": ServiceStatus::parse_all(&result.stdout),
        }))
    },
    Status: ServiceRequest => {
        let args = payload.scope.command_args_as([
            "--no-pager",
            "--plain",
            "status",
            positional("service", &payload.service)?,
        ], as_apps("status", user));
        Ok(run_for(&INFO, "status", user, "systemctl", &args, false)?.into_json())
    },
    Logs: ServiceLogsRequest => {
        // `journalctl -u <unit>` follows the unit's journal across
        // whatever files it spans; `-n` caps the tail to keep payloads
        // bounded. `logs` is a read and therefore never dry-run.
        let lines = payload.lines.to_string();
        // Not `positional`: `-u` takes the next argument as its value, and
        // `-.mount` is a real unit.
        let service = payload.service.as_str();
        // `journalctl --user` reads the journal of whoever runs it, so root
        // matches the apps account's entries by UID instead.
        let (uid, unit);
        let args = if payload.scope == ServiceScope::Apps && !as_apps("logs", user) {
            uid = format!("_UID={}", AppsAccount::resolve().uid);
            unit = format!("_SYSTEMD_USER_UNIT={service}");
            vec!["--no-pager", &uid, &unit, "-n", &lines]
        } else {
            payload.scope.command_args_as(
                ["--no-pager", "-u", service, "-n", &lines],
                as_apps("logs", user),
            )
        };
        Ok(run_for(&INFO, "logs", user, "journalctl", &args, false)?.into_json())
    },
    // `systemctl <verb> <service>` for the single-service mutations.
    Start: ServiceRequest => unit_verb("start", &payload, user),
    Stop: ServiceRequest => unit_verb("stop", &payload, user),
    Restart: ServiceRequest => unit_verb("restart", &payload, user),
    Enable: ServiceRequest => unit_verb("enable", &payload, user),
    Disable: ServiceRequest => unit_verb("disable", &payload, user),
    DaemonReload: DaemonReloadRequest => {
        let args = payload.scope.command_args(["daemon-reload"]);
        Ok(run_for(&INFO, "daemon_reload", user, "systemctl", &args, payload.dry_run)?.into_json())
    },
});

/// Whether `action` runs as the apps account (`run_as: apps`), which
/// reaches its own manager without `-M`.
fn as_apps(action: &str, user: Option<&str>) -> bool {
    INFO.effective_user(action, user) == Some(APPS_USER)
}

fn unit_verb(verb: &str, payload: &ServiceRequest, user: Option<&str>) -> Result<Value> {
    let args = payload
        .scope
        .command_args([verb, positional("service", &payload.service)?]);
    Ok(run_for(&INFO, verb, user, "systemctl", &args, payload.dry_run)?.into_json())
}

#[cfg(test)]
mod tests {
    use crate::agent::modules::Act;
    use serde_json::json;

    use super::*;

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
                json!({
                    "service": "sshd.service",
                    "scope": ServiceScope::System,
                    "dry_run": true,
                }),
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
                json!({
                    "service": "tetra-demo.service",
                    "scope": ServiceScope::User,
                    "dry_run": true,
                }),
                None,
            )
            .unwrap();

        assert_eq!(
            response["command"],
            "systemctl --user start tetra-demo.service"
        );
    }

    #[test]
    fn apps_scope_reaches_the_apps_accounts_manager() {
        let start = ServicesModule
            .handle(
                "start",
                json!({ "service": "site.service", "scope": "apps", "dry_run": true }),
                // Privileged: root, whoever asked.
                Some(APPS_USER),
            )
            .unwrap();
        assert_eq!(
            start["command"],
            "systemctl --user -M ultramarine-apps@ start site.service"
        );
        let reload = DaemonReload(DaemonReloadRequest {
            scope: ServiceScope::Apps,
            dry_run: true,
        })
        .handle(None)
        .unwrap();
        assert_eq!(
            reload["command"],
            "systemctl --user -M ultramarine-apps@ daemon-reload"
        );
        assert!(as_apps("status", Some(APPS_USER)));
        assert!(!as_apps("status", Some("alice")));
        assert!(!as_apps("restart", Some(APPS_USER)));
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
