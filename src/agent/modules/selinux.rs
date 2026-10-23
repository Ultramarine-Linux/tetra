//! SELinux management module.
//!
//! Wraps the userspace SELinux toolchain (`sestatus`, `getenforce`,
//! `getsebool`, `setsebool`, `semanage fcontext`, `restorecon`) so the
//! control plane can inspect and change policy state through the standard
//! module envelope.
//!
//! This module owns *policy-level* SELinux operations: querying mode,
//! flipping booleans, and registering or removing file-context rules plus
//! relabeling. Modules that merely *apply* a label to a path they manage
//! (storage, samba, nfs, files, quadlets, network) do not call into this
//! code; they share the `SelinuxOptions` payload via `apply_selinux()` in
//! `module_support.rs`.

use itertools::Itertools;
use serde_json::json;

use crate::actions;
use crate::agent::module_support::{ModuleInfo, ModuleStatus, NO_ARGS, positional, run_for};
use crate::agent::modules::Mod;
use crate::prelude::*;

/// SELinux module entry point registered under feature `selinux`.
///
/// Stateless: every action is a fresh invocation of an underlying SELinux
/// tool, so there is nothing to hold across requests.
#[derive(Clone, Copy, Debug)]
pub struct SelinuxModule;

/// Static capability metadata published via the `capabilities`/`plan` actions.
const INFO: ModuleInfo = ModuleInfo {
    name: "selinux",
    feature: "selinux",
    description: "Inspect and manage SELinux mode, booleans, file contexts, and relabeling.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "status",
        "enforce",
        "booleans",
        "set_boolean",
        "file_contexts",
        "add_file_context",
        "delete_file_context",
        "restore_context",
    ],
    privileged_actions: &[
        "enforce",
        "set_boolean",
        "add_file_context",
        "delete_file_context",
        "restore_context",
    ],
};

impl Mod for SelinuxModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    Status => {
        let result = run_for(&INFO, "status", user, "sestatus", NO_ARGS, false)?;
        Ok(json!({
            "command": result.command, "status": result.status, "stdout": result.stdout, "stderr": result.stderr, "dry_run": result.dry_run,
            "selinux": parse_sestatus(&result.stdout),
        }))
    },
    Enforce => {
        let result = run_for(&INFO, "enforce", user, "getenforce", NO_ARGS, false)?;
        Ok(json!({
            "command": result.command, "status": result.status, "stdout": result.stdout, "stderr": result.stderr, "dry_run": result.dry_run,
            "mode": result.stdout.trim(),
        }))
    },
    Booleans => {
        let result = run_for(&INFO, "booleans", user, "getsebool", ["-a"], false)?;
        Ok(json!({
            "command": result.command, "status": result.status, "stdout": result.stdout, "stderr": result.stderr, "dry_run": result.dry_run,
            "booleans": parse_getsebool(&result.stdout),
        }))
    },
    SetBoolean {
        name: String,
        value: bool,
        #[serde(default = "default_persistent")]
        persistent: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        let mut args = Vec::new();
        if payload.persistent {
            args.push("-P".to_owned());
        }
        positional("name", &payload.name)?;
        args.push(payload.name);
        args.push(boolean_value(payload.value).to_owned());
        Ok(run_for(&INFO, "set_boolean", user, "setsebool", &args, payload.dry_run)?.into_json())
    },
    FileContexts => {
        let result = run_for(&INFO, "file_contexts", user, "semanage", ["fcontext", "-l"], false)?;
        Ok(json!({
            "command": result.command, "status": result.status, "stdout": result.stdout, "stderr": result.stderr, "dry_run": result.dry_run,
            "file_contexts": parse_semanage_fcontext(&result.stdout),
        }))
    },
    AddFileContext {
        path_pattern: String,
        context_type: String,
        #[serde(default)]
        dry_run: bool,
    } => Ok(run_for(
        &INFO, "add_file_context", user,
        "semanage",
        [
            "fcontext",
            "-a",
            "-t",
            positional("context_type", &payload.context_type)?,
            positional("path_pattern", &payload.path_pattern)?,
        ],
        payload.dry_run,
    )?.into_json()),
    DeleteFileContext {
        path_pattern: String,
        #[serde(default)]
        dry_run: bool,
    } => Ok(run_for(
        &INFO, "delete_file_context", user,
        "semanage",
        [
            "fcontext",
            "-d",
            positional("path_pattern", &payload.path_pattern)?,
        ],
        payload.dry_run,
    )?.into_json()),
    RestoreContext {
        path: String,
        #[serde(default)]
        recursive: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        let mut args = Vec::new();
        args.extend(payload.recursive.then_some("-R"));
        args.extend(["-v", positional("path", &payload.path)?]);
        Ok(run_for(
            &INFO, "restore_context", user,
            "restorecon", &args, payload.dry_run,
        )?.into_json())
    },
});

const fn default_persistent() -> bool {
    true
}

const fn boolean_value(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

/// Parses `sestatus` output into a flat object keyed by lowercased,
/// underscore-separated field names (e.g. `SELinux status:` becomes
/// `selinux_status`). Lines without a `Key: value` pair are dropped.
fn parse_sestatus(stdout: &str) -> Value {
    Value::Object(
        (stdout.lines().filter_map(|line| line.split_once(':')))
            .map(|(key, value)| (normalize_key(key), Value::String(value.trim().to_owned())))
            .collect(),
    )
}

/// Parses `getsebool -a` output, one boolean per line as `name --> value`.
///
/// `enabled` normalizes the raw string (`on`/`1`/`true`) to a boolean so
/// callers do not have to re-parse it; the original `value` is preserved too.
fn parse_getsebool(stdout: &str) -> Vec<Value> {
    (stdout.lines().filter_map(|line| line.split_once("-->")))
        .map(|(name, value)| {
            json!({
                "name": name.trim(),
                "enabled": matches!(value.trim(), "on" | "1" | "true"),
                "value": value.trim(),
            })
        })
        .collect()
}

/// Parses `semanage fcontext -l` output.
///
/// Output shape is roughly `PATTERN  FILE_TYPE  CONTEXT`, where `file_type`
/// may be a multi-word phrase like `all files` and `CONTEXT` is a
/// `user:role:type:level` quadruple. The first printed line is a column
/// header and the second is a `----` separator; both are filtered out below.
fn parse_semanage_fcontext(stdout: &str) -> Vec<Value> {
    (stdout.lines().map(str::trim))
        .filter(|line| !line.is_empty())
        // Drop the column header and the underline separator that semanage
        // prints at the top of its output.
        .filter(|line| !line.starts_with("SELinux fcontext") && !line.starts_with('-'))
        .filter_map(|line| {
            let fields = line.split_whitespace().collect_vec();
            // The context is always the last whitespace-delimited field; the
            // middle fields collapse back into the `file_type` string.
            let [path_pattern, file_type @ .., context] = &fields[..] else {
                return None;
            };
            Some(json!({
                "path_pattern": path_pattern,
                "file_type": file_type.join(" "),
                "context": context,
                "context_type": extract_context_type(context),
            }))
        })
        .collect()
}

/// Pulls the SELinux *type* out of a `user:role:type:level` context string.
///
/// The type is the third colon-separated field — the part callers actually
/// compare against labels like `container_file_t` or `samba_share_t`.
fn extract_context_type(context: &str) -> Option<&str> {
    context.split(':').nth(2)
}

/// Normalizes a `sestatus` field name into a stable JSON key: trimmed,
/// lowercased, with spaces and dashes turned into underscores.
fn normalize_key(key: &str) -> String {
    key.trim().to_lowercase().replace([' ', '-'], "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::modules::Act;

    #[test]
    fn parses_sestatus_output() {
        let status = parse_sestatus(
            "SELinux status:                 enabled\nCurrent mode:                   enforcing\nPolicy version:                 33\n",
        );
        assert_eq!(status["selinux_status"], "enabled");
        assert_eq!(status["current_mode"], "enforcing");
        assert_eq!(status["policy_version"], "33");
    }

    #[test]
    fn parses_getsebool_output() {
        let booleans = parse_getsebool("virt_use_nfs --> off\nhttpd_can_network_connect --> on\n");
        assert_eq!(booleans.len(), 2);
        assert_eq!(booleans[0]["name"], "virt_use_nfs");
        assert_eq!(booleans[0]["enabled"], false);
        assert_eq!(booleans[1]["enabled"], true);
    }

    #[test]
    fn parses_semanage_fcontext_output() {
        let contexts = parse_semanage_fcontext(
            "SELinux fcontext                                   type               Context\n\
             /srv/tetra(/.*)?                                  all files          system_u:object_r:container_file_t:s0\n",
        );
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0]["path_pattern"], "/srv/tetra(/.*)?");
        assert_eq!(contexts[0]["file_type"], "all files");
        assert_eq!(contexts[0]["context_type"], "container_file_t");
    }

    #[test]
    fn dry_run_set_boolean_does_not_call_setsebool() {
        let response = SetBoolean {
            name: "virt_use_nfs".into(),
            value: true,
            persistent: true,
            dry_run: true,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["command"], "setsebool -P virt_use_nfs on");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }

    #[test]
    fn dry_run_restore_context_does_not_call_restorecon() {
        let response = RestoreContext {
            path: "/srv/tetra".into(),
            recursive: true,
            dry_run: true,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["command"], "restorecon -R -v /srv/tetra");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }

    fn selinux_tool_available(tool: &str) -> bool {
        std::process::Command::new(tool)
            .status()
            .err()
            .is_none_or(|error| error.kind() != std::io::ErrorKind::NotFound)
    }

    #[test]
    fn status_parses_selinux_state() {
        if !selinux_tool_available("sestatus") {
            return;
        }

        let response = Status {}.handle(None).unwrap();
        assert!(response["selinux"].is_object());
        assert!(response["command"].as_str().unwrap().contains("sestatus"));
    }

    #[test]
    fn enforce_returns_current_mode() {
        if !selinux_tool_available("getenforce") {
            return;
        }

        let response = Enforce {}.handle(None).unwrap();
        assert!(response["mode"].is_string());
        let mode = response["mode"].as_str().unwrap();
        assert!(mode == "Enforcing" || mode == "Permissive" || mode == "Disabled");
    }

    #[test]
    fn add_file_context_dry_run_previews_command() {
        let response = AddFileContext {
            path_pattern: "/srv/app(/.*)?".into(),
            context_type: "container_file_t".into(),
            dry_run: true,
        }
        .handle(None)
        .unwrap();

        assert_eq!(
            response["command"],
            "semanage fcontext -a -t container_file_t /srv/app(/.*)?"
        );
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }

    #[test]
    fn delete_file_context_dry_run_previews_command() {
        let response = DeleteFileContext {
            path_pattern: "/srv/app(/.*)?".into(),
            dry_run: true,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["command"], "semanage fcontext -d /srv/app(/.*)?");
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }
}
