//! Podman container, image, volume, and network inspection and lifecycle.
//!
//! A thin wrapper around the `podman` CLI. The listing actions (`containers`,
//! `images`, `volumes`, `networks`, `inspect`) all rely on podman's native
//! `--format json`, so [`run_command_json`] parses stdout straight into the
//! response `data` field with no module-specific parsing of our own. The
//! mutating lifecycle actions (`start`/`stop`/`restart`/`remove`) honor the
//! shared `dry_run` flag. Note the action name `remove` maps to the `podman rm`
//! subcommand, keeping the protocol verb consistent across modules while the
//! underlying CLI uses its native spelling.

use crate::prelude::*;

/// Marker type for the podman module. Stateless; all behavior lives in the
/// [`Mod`] impl and the static [`INFO`] descriptor.
#[derive(Clone, Copy, Debug)]
pub struct PodmanModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "podman",
    feature: "podman",
    description: "Inspect and manage Podman containers, images, volumes, networks, and logs.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "containers",
        "inspect",
        "images",
        "volumes",
        "networks",
        "logs",
        "start",
        "stop",
        "restart",
        "remove",
    ],
    privileged_actions: &["start", "stop", "restart", "remove"],
};

impl Mod for PodmanModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    Containers => {
        crate::cmd!({ &INFO, "containers", user } "podman" ["ps", "--all", "--format", "json"] JSON)
    },
    Inspect { name: String } => {
        crate::cmd!({ &INFO, "inspect", user } "podman" ["inspect", &payload.name] JSON)
    },
    Images => {
        crate::cmd!({ &INFO, "images", user } "podman" ["images", "--format", "json"] JSON)
    },
    Volumes => {
        crate::cmd!({ &INFO, "volumes", user } "podman" ["volume", "ls", "--format", "json"] JSON)
    },
    Networks => {
        crate::cmd!({ &INFO, "networks", user } "podman" ["network", "ls", "--format", "json"] JSON)
    },
    Logs {
        name: String,
        #[serde(default = "default_log_lines")]
        lines: u16,
    } => {
        crate::cmd!({ &INFO, "logs", user } "podman" ["logs", "--tail", &payload.lines.to_string(), &payload.name] json)
    },
    Start {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        crate::cmd!((payload.dry_run) { &INFO, "start", user } "podman" ["start", &payload.name] json)
    },
    Stop {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        crate::cmd!((payload.dry_run) { &INFO, "stop", user } "podman" ["stop", &payload.name] json)
    },
    Restart {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        crate::cmd!((payload.dry_run) { &INFO, "restart", user } "podman" ["restart", &payload.name] json)
    },
    Remove {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        crate::cmd!((payload.dry_run) { &INFO, "remove", user } "podman" ["rm", &payload.name] json)
    }
});

const fn default_log_lines() -> u16 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_remove_does_not_call_podman() {
        let response = Remove {
            name: "app".into(),
            dry_run: true,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["command"], "podman rm app");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }
}
