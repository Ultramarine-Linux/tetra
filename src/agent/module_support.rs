use crate::prelude::*;
use std::{path::Component, process::Command};

use serde_json::json;

/// Whether a module is shipping in this build or is a placeholder for a future
/// feature. The dashboard uses this to grey out planned-but-unavailable
/// modules in the capabilities list.
///
/// Serialized as `"available"`/`"planned"` via `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleStatus {
    Available,
    Planned,
}

/// Static metadata each module exposes about itself.
///
/// Returned by [`AgentModule::info`](super::AgentModule::info) and used to:
/// - answer the dispatcher-level `agent.capabilities` action (lists modules)
/// - answer each module's own `capabilities` action (single-module info)
/// - drive the dashboard's module/action pickers
///
/// `name` and `feature` are `&'static str` because every module holds its
/// `INFO` as a `const` — there's no allocation per dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ModuleInfo {
    pub name: &'static str,
    pub feature: &'static str,
    pub description: &'static str,
    pub status: ModuleStatus,
    pub actions: &'static [&'static str],
    /// Actions that require root privileges and an active elevation grant on
    /// headless hosts. The dashboard uses this to request elevation proactively.
    pub privileged_actions: &'static [&'static str],
}

impl ModuleInfo {
    /// Whether `action` is listed in [`privileged_actions`].
    #[must_use]
    pub fn is_privileged(&self, action: &str) -> bool {
        self.privileged_actions.contains(&action)
    }

    /// Answer a shared metadata action, returning `None` for module-specific
    /// actions so the caller can continue its own dispatch.
    #[must_use]
    pub fn metadata_response(&self, action: &str, payload: &Value) -> Option<Value> {
        match action {
            "capabilities" => Some(json!(self)),
            "plan" => Some(jsonf! {
                "module": self.name,
                self.feature,
                self.status,
                "requested": payload,
            }),
            _ => None,
        }
    }

    /// Select the user for an action: privileged actions always run as root.
    #[must_use]
    pub fn effective_user<'a>(&self, action: &str, user: Option<&'a str>) -> Option<&'a str> {
        (!self.is_privileged(action)).then_some(user).flatten()
    }

    /// Create the uniform unsupported-action error used by all modules.
    ///
    /// # Errors
    /// This method always returns an error.
    pub fn unsupported_action(&self, action: &str) -> Result<Value> {
        bail!("unsupported {} action `{action}`", self.name)
    }
}

/// Handle the shared `capabilities` and `plan` meta-actions that every
/// module supports.
///
/// Convention: each module's `handle` method calls this first and returns
/// `Some(...)` if it matched, then matches on its own module-specific
/// actions. `plan` is a lightweight "what would you do with this payload?"
/// endpoint — it returns the module metadata plus the echoed payload, so
/// the dashboard can show a preview without committing to a dry run.
///
/// Returns `None` when the action isn't one of these meta-actions, so the
/// caller can fall through to its own match.
#[must_use]
pub fn handle_metadata(info: ModuleInfo, action: &str, payload: &Value) -> Option<Value> {
    info.metadata_response(action, payload)
}

/// Bail with a consistent "unknown action" error message. Centralizing this
/// keeps the error format uniform across modules.
#[allow(clippy::missing_errors_doc)]
pub fn unsupported_action(module: &str, action: &str) -> Result<Value> {
    bail!("unsupported {module} action `{action}`")
}

#[derive(Debug, Deserialize)]
pub struct NamedPayload {
    pub name: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
pub struct ServicePayload {
    pub service: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// The shared SELinux labeling options accepted by any module that creates or
/// manages host paths.
///
/// This is the dashboard's single knob for "label this path too" — e.g. a
/// Samba share's `set_config` action can label the share directory in the same
/// call that writes `smb.conf`. See [`apply_selinux`] for the semantics.
///
/// `enabled` exists as an explicit opt-in flag so callers can pass a fully
/// populated object in JSON without triggering labeling — they'd just leave
/// `enabled` at its default `false`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SelinuxOptions {
    #[serde(default)]
    pub enabled: bool,
    pub path: Option<String>,
    pub path_pattern: Option<String>,
    pub context_type: Option<String>,
    #[serde(default)]
    pub recursive: bool,
}

/// The payload of an action that takes none: an object, whose fields are
/// ignored as other payloads ignore unknown ones. [`parse_action`] reads an
/// omitted payload (`null`) as `{}`.
// Braces, because a unit struct deserializes from `null` but not `{}`.
#[allow(clippy::empty_structs_with_brackets)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct NoPayload {}

/// Decode `action` and its `payload` into an action enum.
///
/// The enum's variants are named after the actions in snake case
/// (`{"<action>": <payload>}`). An omitted payload (`null`) is read as `{}`, so an action whose payload
/// fields all have defaults may leave it out.
///
/// # Errors
/// Errs on an unknown action or a payload the action does not accept.
pub fn parse_action<T: serde::de::DeserializeOwned>(action: &str, payload: Value) -> Result<T> {
    let payload = if payload.is_null() { json!({}) } else { payload };
    Ok(serde_json::from_value(json!({ action: payload }))?)
}

/// Deserialize a typed payload from a [`serde_json::Value`] with a consistent
/// "invalid command payload" error message. Centralizing this keeps the
/// per-module error surface uniform.
///
/// # Errors
/// An error is returned if the payload cannot be deserialized.
pub fn parse_payload<T: for<'de> Deserialize<'de>>(payload: Value) -> Result<T> {
    serde_json::from_value(payload).context("invalid command payload")
}

/// Whether the module supports running non-privileged actions as a non-root
/// user via `runuser`. When `true`, safe actions can be executed unprivileged
/// by passing a user to the `_for_module` helpers.
pub const DEFAULT_USER_SUPPORT: bool = cfg!(target_os = "linux");

/// Execute commands. Wrapper around [`run_command_output_as`].
///
/// # Usage
/// - prefix `DRY_RUN` or `DRY_RUN(bool_expr)` to set dry run
/// - prefix `{ &INFO, action, user }` to set default user
/// - then add your program name (any expression)
/// - add `=> args` for your arguments (`args` need to be `Copy`!)
/// - add `; json` to wrap it around [`serde_json::json!`]
/// - add `; JSON` to obtain json in the following format:
/// ```ts
/// {
///     "command": result.command,
///     "status": result.status,
///     "stdout": result.stdout,
///     "stderr": result.stderr,
///     "dry_run": result.dry_run,
///     "data": stdout,
/// }
/// ```
///
/// For aesthetic/formatting purposes, the macro partially accepts usages with elided `;` or `=>`.
#[macro_export]
macro_rules! cmd {
    ($($idk:tt)+) => {
        $crate::__cmd_inner!((false, None) $($idk)+)
    };
}

#[macro_export]
macro_rules! __cmd_inner {
    (($dry_run:expr, $default_user:expr) DRY_RUN($dry:expr) $($idk:tt)+) => {
        $crate::__cmd_inner!(($dry, $default_user) $($idk)+)
    };
    (($dry_run:expr, $default_user:expr) ($dry:expr) $($idk:tt)+) => {
        $crate::__cmd_inner!(($dry, $default_user) $($idk)+)
    };
    (($dry_run:expr, $default_user:expr) DRY_RUN $($idk:tt)+) => {
        $crate::__cmd_inner!((true, $default_user) $($idk)+)
    };
    (($dry_run:expr, $default_user:expr) { $info:expr, $act:expr, $user:expr } $($idk:tt)+) => {{
        let default_user = $crate::agent::module_support::effective_user($info, $act, $user);
        $crate::__cmd_inner!(($dry_run, default_user) $($idk)+)
    }};
    (($dry_run:expr, $default_user:expr) $program:literal $args:expr $(; $($idk:tt)*)?) => {
        $crate::__cmd_inner!(
            @{$($($idk)*)?}
            $crate::agent::module_support::run_command_output_as($program, $args, $dry_run, $default_user)
        )
    };
    (($dry_run:expr, $default_user:expr) $program:literal [$($args:tt)+] $($idk:tt)*) => {
        $crate::__cmd_inner!(
            @{$($idk)*}
            $crate::agent::module_support::run_command_output_as($program, [$($args)+], $dry_run, $default_user)
        )
    };
    (($dry_run:expr, $default_user:expr) $program:expr $(; $($idk:tt)*)?) => {
        $crate::__cmd_inner!(
            @{$($($idk)*)?}
            $crate::agent::module_support::run_command_output_as($program, &[""; 0], $dry_run, $default_user)
        )
    };
    (($dry_run:expr, $default_user:expr) $program:expr => $args:expr $(; $($idk:tt)*)?) => {
        $crate::__cmd_inner!(
            @{$($($idk)*)?}
            $crate::agent::module_support::run_command_output_as($program, $args, $dry_run, $default_user)
        )
    };
    (($dry_run:expr, $default_user:expr) $program:expr => [$($args:tt)+] $($idk:tt)*) => {
        $crate::__cmd_inner!(
            @{$($idk)*}
            $crate::agent::module_support::run_command_output_as($program, [$($args)+], $dry_run, $default_user)
        )
    };
    (@{}$final:expr) => { $final };
    (@{json}$final:expr) => { $final.map(|obj| ::serde_json::json!(obj)) };
    (@{JSON}$final:expr) => { $final.and_then(|result| {
        let data: ::serde_json::Value =
            ::serde_json::from_str(&result.stdout).context("failed to parse command stdout as JSON")?;
        Ok($crate::jsonf! { result.command, result.status, result.stdout, result.stderr, result.dry_run, data })
    }) };
}

/// Run a host command, optionally impersonating `default_user`.
///
/// When `default_user` is `Some`, the command is wrapped in
/// `runuser -u <user> -- <program> <args>`.  This lets Tetra run as root
/// while executing day-to-day operations (podman inspect, reading configs)
/// with unprivileged credentials.  Privileged actions bypass this wrapper
/// by passing `default_user: None`.
///
/// # Errors
/// An error is returned if the command fails to start, or if it exits with a non-zero status code.
pub fn run_command_output_as<I, S>(
    program: &str,
    args: I,
    dry_run: bool,
    default_user: Option<&str>,
) -> Result<CommandResult>
where
    I: IntoIterator<Item = S> + Copy,
    S: AsRef<OsStr> + std::fmt::Display,
{
    let command = command_display(program, args);

    if dry_run {
        return Ok(CommandResult {
            command,
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            dry_run: true,
        });
    }

    let output = match default_user {
        Some(user) if DEFAULT_USER_SUPPORT && current_uid_is_root() => Command::new("runuser")
            .args(["-u", user, "--", program])
            .args(args)
            .output()
            .with_context(|| format!("failed to run `{program}` as `{user}`")),
        Some(user) => Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to run `{program}` as current user `{user}`")),
        _ => Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to run `{program}`")),
    }?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code();

    if !output.status.success() {
        bail!("`{command}` failed with status {code:?}: {}", stderr.trim());
    }

    Ok(CommandResult {
        command,
        status: code,
        stdout,
        stderr,
        dry_run: false,
    })
}

/// Run `program` with `input` on its stdin, as Tetra's own user.
///
/// For a secret that must not appear on a command line, where any local user
/// can read it. `display` stands in for the command in the result and in
/// errors, so it must not contain the secret either.
///
/// # Errors
/// Fails when the command cannot start, or exits with a non-zero status.
pub fn run_command_with_input(
    program: &str,
    args: &[&str],
    input: &[u8],
    display: String,
    dry_run: bool,
) -> Result<CommandResult> {
    use std::{io::Write as _, process::Stdio};
    if dry_run {
        return Ok(CommandResult {
            command: display,
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            dry_run: true,
        });
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run `{program}`"))?;
    // A command that exits without reading closes the pipe; its status says
    // more than the failed write.
    let written = child.stdin.take().context("no stdin")?.write_all(input);
    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to run `{program}`"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code();
    ensure!(
        output.status.success(),
        "`{display}` failed with status {code:?}: {}",
        stderr.trim()
    );
    written.with_context(|| format!("failed to write to `{display}`"))?;
    Ok(CommandResult {
        command: display,
        status: code,
        stdout,
        stderr,
        dry_run: false,
    })
}

#[cfg(target_os = "linux")]
fn current_uid_is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn current_uid_is_root() -> bool {
    false
}

/// Compute the effective OS user for a module action.
///
/// Privileged actions always run as root (`None`). Unprivileged actions run as
/// the supplied `user` when it is present, otherwise they fall back to root.
#[inline]
#[must_use]
pub fn effective_user<'a>(
    info: &ModuleInfo,
    action: &str,
    user: Option<&'a str>,
) -> Option<&'a str> {
    info.effective_user(action, user)
}

/// Apply SELinux file-context labeling to a path as part of a module action.
///
/// Two phases:
/// 1. If `context_type` is set, run `semanage fcontext -a -t <type>
///    <pattern>` to register the persistent label rule. The pattern is taken
///    from `path_pattern` if present, otherwise derived from `path` (with
///    `(/.*)?` appended when `recursive` is set, matching the convention
///    `restorecon` expects).
/// 2. If `path` is set, run `restorecon [-R] -v <path>` to apply the label
///    immediately. `restorecon` reads the fcontext database, so it must run
///    *after* the `semanage` call.
///
/// Returns one [`Value`] per operation performed (so the dashboard can show
/// what was done), and is a no-op when the options are absent or `enabled`
/// is `false` and no other field triggers a label.
///
/// `default_path` is the path the calling module is already acting on (e.g.
/// the Samba share directory); it's used only when the caller didn't pass an
/// explicit `path` in the options. This lets the dashboard send a minimal
/// `{ "context_type": "samba_share_t" }` payload and have the module's own
/// context fill in the path.
///
/// Dry-run mode propagates to both `semanage` and `restorecon` calls, so a
/// dry-run preview of the *whole* action (e.g. write smb.conf + label it)
/// shows the exact commands without changing the host.
///
/// # Errors
/// An error is returned if `context_type` is set but no pattern can be derived.
/// Command errors are also propagated.
pub fn apply_selinux(
    options: Option<&SelinuxOptions>,
    default_path: Option<&Path>,
    dry_run: bool,
) -> Result<Vec<Value>> {
    // Build the default `semanage fcontext` pattern for `path`. Recursive
    // labeling appends `(/.*)?` so that `restorecon` relabels the whole subtree;
    // non-recursive labeling targets just the path itself.
    let default_fcontext_pattern = |path: Option<&String>, recursive: bool| {
        path.map(|path| {
            if recursive {
                format!("{path}(/.*)?")
            } else {
                path.to_owned()
            }
        })
    };

    let Some(options) = options else {
        return Ok(Vec::new());
    };

    if !options.enabled
        && options.path.is_none()
        && options.path_pattern.is_none()
        && options.context_type.is_none()
    {
        return Ok(Vec::new());
    }

    let path = (options.path.clone())
        .or_else(|| default_path.map(|path| path.to_string_lossy().into_owned()));
    let mut operations = Vec::new();

    if let Some(context_type) = &options.context_type {
        let pattern = (options.path_pattern.clone())
            .or_else(|| default_fcontext_pattern(path.as_ref(), options.recursive))
            .context("SELinux context_type requires path, path_pattern, or default path")?;
        operations.push(
            cmd!((dry_run) "semanage" ["fcontext", "-a", "-t", context_type, &pattern] json)?,
        );
    }

    if let Some(path) = path.as_deref() {
        let mut args = Vec::new();
        args.extend(options.recursive.then_some("-R"));
        args.extend_from_slice(&["-v", path]);
        operations.push(cmd!((dry_run) "restorecon" &args ; json)?);
    }

    Ok(operations)
}

/// Run `restorecon <flags> <path>` so `path` gets the policy's default
/// label.
///
/// Skipped on hosts without SELinux, except in a dry run, which always
/// previews it. Returns the commands run, as module responses list them.
///
/// # Errors
/// Fails when `restorecon` fails.
pub fn restorecon(path: &Path, flags: &[&str], dry_run: bool) -> Result<Vec<Value>> {
    if !dry_run && !Path::new("/sys/fs/selinux/enforce").exists() {
        return Ok(Vec::new());
    }
    let path = path.to_string_lossy();
    let mut args = flags.to_vec();
    args.push(&path);
    Ok(vec![cmd!((dry_run) "restorecon" &args ; json)?])
}

/// Whether `systemctl is-enabled` reports `unit` as `enabled`.
#[must_use]
pub fn unit_enabled(unit: &str) -> bool {
    cmd!("systemctl" ["is-enabled", unit]).is_ok_and(|result| result.stdout.trim() == "enabled")
}

/// Tetra's drop-in for `unit` in `systemd_dir`
/// (`<systemd_dir>/<unit>.d/50-tetra.conf`).
#[must_use]
pub fn drop_in(systemd_dir: &Path, unit: &str) -> PathBuf {
    systemd_dir.join(format!("{unit}.d")).join("50-tetra.conf")
}

/// Install the drop-in at `path` (mode `0644`) with `contents`, returning
/// whether it changed. A dry run only compares.
///
/// # Errors
/// Fails when the drop-in cannot be written.
pub fn install_drop_in(path: &Path, contents: &str, dry_run: bool) -> Result<bool> {
    if dry_run {
        return Ok(fs::read(path).ok().as_deref() != Some(contents.as_bytes()));
    }
    crate::auth::store::replace_if_changed(path, contents.as_bytes(), 0o644)
}

/// Join `name` onto `base`, rejecting absolute paths or any component that
/// would escape `base` (`..`, Windows prefixes).
///
/// This is the guard against path-traversal in module payloads — e.g. a
/// Quadlet filename from the dashboard can't reach outside the Quadlet scan
/// directory by sending `../../../etc/passwd`.
///
/// # Errors
/// An error is returned if `name` is absolute or contains any parent-directory
pub fn safe_join(base: &Path, name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        bail!("path `{name}` must be relative and stay within the base directory");
    }

    Ok(base.join(path))
}

/// Render a command and its args as a single space-joined display string.
/// Used both for dry-run previews and for error messages (`` `foo bar` failed ``).
#[must_use]
pub fn command_display<I: IntoIterator<Item = S>, S: std::fmt::Display, P: std::fmt::Display>(
    program: P,
    args: I,
) -> String {
    let args = (args.into_iter()).map(|arg| Box::new(arg) as Box<dyn std::fmt::Display>);
    (std::iter::once(Box::new(program) as Box<dyn std::fmt::Display>).chain(args)).join(" ")
}

/// The result of running (or dry-running) a host command. Serialized as JSON
/// by the `run_command*` helpers and returned to the dashboard so the UI can
/// show what actually ran, not just the final value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandResult {
    pub command: String,
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub dry_run: bool,
}

/// Runs a program with arguments, for [`Commands`].
type Runner<'a> = dyn FnMut(&str, &[&str]) -> Result<CommandResult> + 'a;

/// The commands one action runs (or plans, in a dry run), in order, for its
/// response: each as its [`CommandResult`], or `{command, error}` when it
/// failed.
pub struct Commands<'a> {
    dry_run: bool,
    runner: Box<Runner<'a>>,
    /// What ran so far.
    pub done: Vec<Value>,
}

impl<'a> Commands<'a> {
    /// Run commands as root with [`run_command_output_as`].
    #[must_use]
    pub fn new(dry_run: bool) -> Self {
        Self::with_runner(dry_run, move |program, args| {
            run_command_output_as(program, args, dry_run, None)
        })
    }

    /// Run commands with `runner` (a fake, in tests).
    pub fn with_runner<F>(dry_run: bool, runner: F) -> Self
    where
        F: FnMut(&str, &[&str]) -> Result<CommandResult> + 'a,
    {
        Self {
            dry_run,
            runner: Box::new(runner),
            done: Vec::new(),
        }
    }

    /// A fake for tests: every command succeeds, except the command line
    /// `failing`.
    #[cfg(test)]
    #[must_use]
    pub fn fake(dry_run: bool, failing: &'a str) -> Self {
        Self::with_runner(dry_run, move |program, args| {
            let command = command_display(program, args);
            ensure!(command != failing, "`{command}` failed");
            Ok(CommandResult {
                command,
                status: (!dry_run).then_some(0),
                stdout: String::new(),
                stderr: String::new(),
                dry_run,
            })
        })
    }

    #[must_use]
    pub const fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Run a command and record it, failed or not.
    ///
    /// # Errors
    /// Fails when the command does.
    pub fn run(&mut self, program: &str, args: &[&str]) -> Result<()> {
        let result = (self.runner)(program, args);
        self.done.push(match &result {
            Ok(result) => serde_json::to_value(result)?,
            Err(error) => json!({
                "command": command_display(program, args),
                "error": error.to_string(),
            }),
        });
        result.map(drop)
    }

    /// Run a command whose failure does not stop the action (cleanup of
    /// state that may not exist). Returns whether it succeeded.
    pub fn run_ignoring_failure(&mut self, program: &str, args: &[&str]) -> bool {
        self.run(program, args).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Payload {
        name: String,
    }

    #[test]
    fn parses_typed_payloads() {
        let payload: Payload = parse_payload(json!({ "name": "example" })).unwrap();
        assert_eq!(
            payload,
            Payload {
                name: "example".into()
            }
        );
    }

    #[test]
    fn rejects_invalid_typed_payloads() {
        let error = parse_payload::<Payload>(json!({ "other": true })).unwrap_err();
        assert!(error.to_string().contains("invalid command payload"));
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum Action {
        Status(NoPayload),
        Disable {
            #[serde(default)]
            dry_run: bool,
        },
        Remove {
            name: String,
        },
    }

    #[test]
    fn actions_take_null_for_an_empty_payload() {
        for payload in [Value::Null, json!({}), json!({ "x": 1 })] {
            let action: Action = parse_action("status", payload).unwrap();
            assert_eq!(action, Action::Status(NoPayload {}));
        }
        for payload in [json!(""), json!(false), json!([1])] {
            parse_action::<Action>("status", payload).unwrap_err();
        }
        // Defaulted fields may be left out with the whole payload.
        let action: Action = parse_action("disable", Value::Null).unwrap();
        assert_eq!(action, Action::Disable { dry_run: false });
        // Required ones may not.
        parse_action::<Action>("remove", Value::Null).unwrap_err();
        parse_action::<Action>("other", Value::Null).unwrap_err();
    }

    #[test]
    fn drop_ins_are_installed_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = drop_in(dir.path(), "example.service");
        assert_eq!(path, dir.path().join("example.service.d/50-tetra.conf"));
        // A dry run only compares.
        assert!(install_drop_in(&path, "[Service]\n", true).unwrap());
        assert!(!path.exists());
        assert!(install_drop_in(&path, "[Service]\n", false).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "[Service]\n");
        assert!(!install_drop_in(&path, "[Service]\n", true).unwrap());
        assert!(!install_drop_in(&path, "[Service]\n", false).unwrap());
        assert!(install_drop_in(&path, "[Unit]\n", false).unwrap());
    }

    #[test]
    fn safe_join_rejects_paths_that_escape_base() {
        let base = Path::new("/tmp/base");
        assert_eq!(
            safe_join(base, "unit.container").unwrap(),
            base.join("unit.container")
        );
        safe_join(base, "../unit.container").unwrap_err();
        safe_join(base, "/tmp/unit.container").unwrap_err();
    }

    #[test]
    fn formats_command_display() {
        assert_eq!(
            command_display("systemctl", ["status", "nginx.service"]),
            "systemctl status nginx.service"
        );
    }

    #[test]
    fn commands_record_failures_too() {
        let mut commands = Commands::fake(false, "systemctl stop b");
        commands.run("systemctl", &["stop", "a"]).unwrap();
        let error = commands.run("systemctl", &["stop", "b"]).unwrap_err();
        assert!(error.to_string().contains("systemctl stop b"));
        assert!(!commands.run_ignoring_failure("systemctl", &["stop", "b"]));
        assert!(commands.run_ignoring_failure("systemctl", &["stop", "c"]));
        assert_eq!(commands.done[0]["command"], "systemctl stop a");
        assert_eq!(commands.done[0]["status"], 0);
        for failed in &commands.done[1..3] {
            assert_eq!(failed["command"], "systemctl stop b");
            assert_eq!(failed["error"], "`systemctl stop b` failed");
        }
        assert_eq!(commands.done[3]["command"], "systemctl stop c");

        let mut plan = Commands::new(true);
        assert!(plan.dry_run());
        plan.run("definitely-not-a-real-command", &["x"]).unwrap();
        assert_eq!(plan.done[0]["dry_run"], true);
    }

    #[test]
    fn input_goes_to_stdin_and_stays_out_of_the_result() {
        let display = || "cat <secret>".to_owned();
        let result = run_command_with_input("cat", &[], b"hunter2", display(), false).unwrap();
        assert_eq!(result.stdout, "hunter2");
        assert_eq!(result.command, "cat <secret>");
        assert_eq!(result.status, Some(0));

        let error = run_command_with_input(
            "sh",
            &["-c", "cat >/dev/null; echo nope >&2; exit 3"],
            b"hunter2",
            "sh <secret>".into(),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("`sh <secret>` failed"), "{error}");
        assert!(error.contains("nope"), "{error}");
        assert!(!error.contains("hunter2") && !error.contains("cat"), "{error}");

        let result =
            run_command_with_input("definitely-not-a-real-command", &[], b"x", display(), true)
                .unwrap();
        assert!(result.dry_run);
        assert_eq!(result.command, "cat <secret>");
    }

    #[test]
    fn dry_run_command_does_not_execute() {
        let result = cmd!(DRY_RUN "definitely-not-a-real-command" ["arg"]).unwrap();
        assert_eq!(result.command, "definitely-not-a-real-command arg");
        assert!(result.dry_run);
        assert_eq!(result.status, None);
        let result = cmd!((true) "definitely-not-a-real-command" ["arg"]).unwrap();
        assert_eq!(result.command, "definitely-not-a-real-command arg");
        assert!(result.dry_run);
        assert_eq!(result.status, None);
    }

    #[test]
    fn selinux_helper_builds_fcontext_and_restorecon_commands() {
        let options = SelinuxOptions {
            enabled: true,
            path: None,
            path_pattern: None,
            context_type: Some("samba_share_t".into()),
            recursive: true,
        };
        let operations =
            apply_selinux(Some(&options), Some(Path::new("/srv/share")), true).unwrap();

        assert_eq!(operations.len(), 2);
        assert_eq!(
            operations[0]["command"],
            "semanage fcontext -a -t samba_share_t /srv/share(/.*)?"
        );
        assert_eq!(operations[1]["command"], "restorecon -R -v /srv/share");
    }

    #[test]
    fn selinux_helper_is_noop_when_not_requested() {
        let operations = apply_selinux(
            Some(&SelinuxOptions::default()),
            Some(Path::new("/srv/share")),
            true,
        )
        .unwrap();
        assert_eq!(operations, Vec::<Value>::new());
    }
}
