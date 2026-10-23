//! Podman container, image, volume, and network inspection and lifecycle.
//!
//! A thin wrapper around the `podman` CLI. The listing actions (`containers`,
//! `images`, `volumes`, `networks`, `inspect`) all rely on podman's native
//! `--format json`, so `CommandResult::into_json_stdout` parses stdout
//! straight into the response `data` field with no module-specific parsing of
//! our own. The
//! mutating lifecycle actions (`start`/`stop`/`restart`/`remove`) honor the
//! shared `dry_run` flag. Note the action name `remove` maps to the `podman rm`
//! subcommand, keeping the protocol verb consistent across modules while the
//! underlying CLI uses its native spelling.
//!
//! Reads run as the `ultramarine-apps` account by default
//! ([`Mod::default_run_as`]), since that is where user apps' containers live;
//! `run_as` picks the signed-in user or root instead. `inspect` hides
//! environment values unless an administrator sends `show_env: true`.

use crate::agent::module_support::{positional, run_for};
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

    /// User apps' containers are the apps account's, so that is the view
    /// reads show unless the payload says otherwise.
    fn default_run_as(&self) -> RunAs {
        RunAs::Apps
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    Containers => {
        run_for(
            &INFO, "containers", user,
            "podman", ["ps", "--all", "--format", "json"], false,
        )?.into_json_stdout()
    },
    Inspect {
        name: String,
        #[serde(default)]
        show_env: bool,
    } => {
        let mut result = run_for(
            &INFO, "inspect", user,
            "podman", ["inspect", positional("name", &payload.name)?], false,
        )?.into_json_stdout()?;
        if !payload.show_env {
            redact_env(&mut result);
        }
        Ok(result)
    },
    Images => {
        run_for(
            &INFO, "images", user,
            "podman", ["images", "--format", "json"], false,
        )?.into_json_stdout()
    },
    Volumes => {
        run_for(
            &INFO, "volumes", user,
            "podman", ["volume", "ls", "--format", "json"], false,
        )?.into_json_stdout()
    },
    Networks => {
        run_for(
            &INFO, "networks", user,
            "podman", ["network", "ls", "--format", "json"], false,
        )?.into_json_stdout()
    },
    Logs {
        name: String,
        #[serde(default = "default_log_lines")]
        lines: u16,
    } => {
        Ok(run_for(
            &INFO, "logs", user,
            "podman",
            [
                "logs",
                "--tail",
                &payload.lines.to_string(),
                positional("name", &payload.name)?,
            ],
            false,
        )?.into_json())
    },
    Start {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        Ok(run_for(
            &INFO, "start", user,
            "podman", ["start", positional("name", &payload.name)?], payload.dry_run,
        )?.into_json())
    },
    Stop {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        Ok(run_for(
            &INFO, "stop", user,
            "podman", ["stop", positional("name", &payload.name)?], payload.dry_run,
        )?.into_json())
    },
    Restart {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        Ok(run_for(
            &INFO, "restart", user,
            "podman", ["restart", positional("name", &payload.name)?], payload.dry_run,
        )?.into_json())
    },
    Remove {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        Ok(run_for(
            &INFO, "remove", user,
            "podman", ["rm", positional("name", &payload.name)?], payload.dry_run,
        )?.into_json())
    }
});

const fn default_log_lines() -> u16 {
    100
}

/// What `inspect` shows in place of an environment value.
const REDACTED: &str = "********";

/// Hide environment values in an `inspect` result (its parsed `data` and the
/// raw `stdout`): apps keep secrets there (`Environment=DB_PASSWORD=...`),
/// and the Containers page may see the apps account's containers. Only
/// administrators may ask for them (`show_env`).
fn redact_env(result: &mut Value) {
    let Some(entries) = result["data"].as_array_mut() else {
        return;
    };
    let redact = |entry: &mut Value| {
        let key = entry
            .as_str()
            .and_then(|pair| pair.split_once('='))
            .map(|(key, _)| key.to_owned());
        if let Some(key) = key {
            *entry = Value::String(format!("{key}={REDACTED}"));
        }
    };
    for entry in &mut *entries {
        let config = &mut entry["Config"];
        if let Some(env) = config.get_mut("Env").and_then(Value::as_array_mut) {
            env.iter_mut().for_each(redact);
        }
        // Quadlet passes `Environment=` as `--env KEY=VALUE`.
        if let Some(args) = config.get_mut("CreateCommand").and_then(Value::as_array_mut) {
            let mut value_follows = false;
            for arg in &mut *args {
                let flag = arg.as_str().unwrap_or_default();
                if value_follows {
                    redact(arg);
                    value_follows = false;
                } else if matches!(flag, "--env" | "-e") {
                    value_follows = true;
                } else if let Some(pair) = flag
                    .strip_prefix("--env=")
                    .or_else(|| flag.strip_prefix("-e="))
                {
                    let key = pair.split_once('=').map_or(pair, |(key, _)| key);
                    *arg = Value::String(format!("--env={key}={REDACTED}"));
                }
            }
        }
    }
    if let Ok(stdout) = serde_json::to_string_pretty(&result["data"]) {
        result["stdout"] = Value::String(stdout);
    }
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

    #[test]
    fn reads_default_to_the_apps_account() {
        assert_eq!(PodmanModule.default_run_as(), RunAs::Apps);
    }

    #[test]
    fn inspect_hides_environment_values() {
        let data = serde_json::json!([{
            "Config": {
                "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2", "EMPTY"],
                "CreateCommand": [
                    "/usr/bin/podman", "run", "--env", "DB_PASSWORD=hunter2",
                    "-e", "TOKEN=s3cret", "--env=KEY=v", "--name", "db",
                ],
            },
        }]);
        let mut result = serde_json::json!({ "stdout": data.to_string(), "data": data });
        redact_env(&mut result);
        let shown = result.to_string();
        assert!(!shown.contains("hunter2") && !shown.contains("s3cret"), "{shown}");
        assert_eq!(
            result["data"][0]["Config"]["Env"],
            serde_json::json!(["PATH=********", "DB_PASSWORD=********", "EMPTY"])
        );
        assert_eq!(
            result["data"][0]["Config"]["CreateCommand"],
            serde_json::json!([
                "/usr/bin/podman", "run", "--env", "DB_PASSWORD=********",
                "-e", "TOKEN=********", "--env=KEY=********", "--name", "db",
            ])
        );
    }
}
