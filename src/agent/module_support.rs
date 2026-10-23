use crate::prelude::*;
use std::{ffi::OsStr, path::Component, process::Command};

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
/// Returned by [`Mod::info`](super::modules::Mod::info) and used to:
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
    /// Whether `action` is listed in [`privileged_actions`](Self::privileged_actions).
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
            "plan" => Some(json!({
                "module": self.name,
                "feature": self.feature,
                "status": self.status,
                "requested": payload,
            })),
            _ => None,
        }
    }

    /// Select the user for an action: privileged actions always run as root.
    #[must_use]
    pub fn effective_user<'a>(&self, action: &str, user: Option<&'a str>) -> Option<&'a str> {
        (!self.is_privileged(action)).then_some(user).flatten()
    }
}

/// Append `flag value` to `args` when `value` is set.
pub fn option_arg(args: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        args.extend([flag.to_owned(), value]);
    }
}

/// Check a payload value that becomes a positional argument of a host
/// command: an empty value or one starting with `-` would be read as an
/// option (`podman rm -a`, `podman logs -f`).
///
/// # Errors
/// Fails when `value` is empty or starts with `-`.
pub fn positional<'a>(field: &str, value: &'a str) -> Result<&'a str> {
    ensure!(
        !value.is_empty() && !value.starts_with('-'),
        "`{field}` must not be empty or start with `-`"
    );
    Ok(value)
}

#[derive(Debug, Deserialize)]
pub struct NamedPayload {
    pub name: String,
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
    let payload = if payload.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        payload
    };
    // `json!({ action: payload })` would serialize a copy of the payload.
    let mut wrapper = serde_json::Map::new();
    wrapper.insert(action.to_owned(), payload);
    Ok(serde_json::from_value(Value::Object(wrapper))?)
}

/// Whether the module supports running non-privileged actions as a non-root
/// user via `runuser`. When `true`, safe actions can be executed unprivileged
/// by passing a user to the `_for_module` helpers.
pub const DEFAULT_USER_SUPPORT: bool = cfg!(target_os = "linux");

/// No arguments, for [`run`], [`run_dry`] and [`run_for`].
pub const NO_ARGS: [&str; 0] = [];

/// Run `program args` as Tetra's own user.
///
/// # Errors
/// See [`run_command_output_as`].
pub fn run<I, S>(program: &str, args: I) -> Result<CommandResult>
where
    I: IntoIterator<Item = S> + Copy,
    S: AsRef<OsStr> + std::fmt::Display,
{
    run_command_output_as(program, args, false, None)
}

/// [`run`], or only plan the command when `dry_run` is set.
///
/// # Errors
/// See [`run_command_output_as`].
pub fn run_dry<I, S>(program: &str, args: I, dry_run: bool) -> Result<CommandResult>
where
    I: IntoIterator<Item = S> + Copy,
    S: AsRef<OsStr> + std::fmt::Display,
{
    run_command_output_as(program, args, dry_run, None)
}

/// Run `program args` for a module's `action`: as `user`, unless the
/// action is privileged ([`ModuleInfo::effective_user`]), and only planned
/// when `dry_run` is set.
///
/// # Errors
/// See [`run_command_output_as`].
pub fn run_for<I, S>(
    info: &ModuleInfo,
    action: &str,
    user: Option<&str>,
    program: &str,
    args: I,
    dry_run: bool,
) -> Result<CommandResult>
where
    I: IntoIterator<Item = S> + Copy,
    S: AsRef<OsStr> + std::fmt::Display,
{
    run_command_output_as(program, args, dry_run, info.effective_user(action, user))
}

/// Upper bound for one host command.
///
/// The dispatch queue runs one command at a time, so a hung child (a `systemctl` job, `virsh`, `podman`) would stall
/// every transport. Generous enough for an image pull during `systemctl start`.
pub const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(15);

impl CommandResult {
    /// The result as JSON: `command`, `status`, `stdout`, `stderr` and
    /// `dry_run`.
    #[must_use]
    pub fn into_json(self) -> Value {
        json!(self)
    }

    /// [`into_json`](Self::into_json), plus stdout parsed as JSON in `data`.
    ///
    /// # Errors
    /// Fails when stdout is not JSON, as it is not in a dry run.
    pub fn into_json_stdout(self) -> Result<Value> {
        let data: Value =
            serde_json::from_str(&self.stdout).context("failed to parse command stdout as JSON")?;
        Ok(json!({
            "command": self.command,
            "status": self.status,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "dry_run": self.dry_run,
            "data": data,
        }))
    }

    const fn planned(command: String) -> Self {
        Self {
            command,
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            dry_run: true,
        }
    }

    fn finish(command: String, output: &std::process::Output) -> Result<Self> {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let status = output.status.code();
        ensure!(
            output.status.success(),
            "`{command}` failed with status {status:?}: {}",
            stderr.trim()
        );
        Ok(Self {
            command,
            status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr,
            dry_run: false,
        })
    }
}

/// `command.output()` with `input` on its stdin (or none), killing the
/// child's process group after [`COMMAND_TIMEOUT`]. Also returns whether
/// all of `input` was written: a command that exits without reading it
/// closes the pipe, and its status says more than the failed write.
pub(crate) fn output_with_timeout(
    command: &mut Command,
    input: Option<&[u8]>,
) -> io::Result<(std::process::Output, io::Result<()>)> {
    use std::{
        io::Write as _,
        os::unix::process::CommandExt as _,
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    fn drain(mut pipe: impl io::Read + Send + 'static) -> thread::JoinHandle<io::Result<Vec<u8>>> {
        thread::spawn(move || {
            let mut buffer = Vec::new();
            pipe.read_to_end(&mut buffer).map(|_| buffer)
        })
    }
    fn join(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
        handle
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("output reader panicked")))
    }

    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so the kill also reaches the program under `runuser`.
        .process_group(0)
        .spawn()?;
    let stdout = drain(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout"))?,
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("no stderr"))?,
    );
    // From a thread of its own, so a child that writes before it reads
    // cannot deadlock against us.
    let writer = match (input, child.stdin.take()) {
        (Some(input), Some(mut stdin)) => {
            let input = input.to_vec();
            Some(thread::spawn(move || stdin.write_all(&input)))
        }
        _ => None,
    };
    let deadline = Instant::now().checked_add(COMMAND_TIMEOUT);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            if let Ok(pid) = i32::try_from(child.id()) {
                let group = nix::unistd::Pid::from_raw(pid);
                nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL).ok();
            }
            child.wait().ok();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out after {COMMAND_TIMEOUT:?}"),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let written = writer.map_or(Ok(()), |writer| {
        writer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("input writer panicked")))
    });
    let output = std::process::Output {
        status,
        stdout: join(stdout)?,
        stderr: join(stderr)?,
    };
    Ok((output, written))
}

/// Run a host command, optionally impersonating `default_user`.
///
/// When `default_user` is `Some` (and Tetra runs as root), the command is
/// wrapped in `runuser -u <user> -- <program> <args>`, with
/// `XDG_RUNTIME_DIR=/run/user/<uid>` when that directory exists (rootless
/// Podman and `systemctl --user` need it; the lingering `ultramarine-apps`
/// account always has one). This lets Tetra run as root while executing
/// day-to-day operations (podman inspect, reading configs) with
/// unprivileged credentials. Privileged actions bypass this wrapper by
/// passing `default_user: None`.
///
/// # Errors
/// An error is returned if the command fails to start, times out, or exits
/// with a non-zero status code.
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
    let display = command_display(program, args);
    if dry_run {
        return Ok(CommandResult::planned(display));
    }
    let mut command = match default_user {
        Some(user) if DEFAULT_USER_SUPPORT && nix::unistd::geteuid().is_root() => {
            let mut command = Command::new("runuser");
            command.args(["-u", user, "--", program]);
            // `runuser` keeps the environment, and Tetra's has no runtime
            // directory: point rootless Podman and `systemctl --user` at
            // the user's manager, when it runs.
            if let Some(runtime_dir) = user_runtime_dir(user) {
                command.env("XDG_RUNTIME_DIR", runtime_dir);
            }
            command
        }
        _ => Command::new(program),
    };
    let (output, _) = output_with_timeout(command.args(args), None)
        .with_context(|| format!("failed to run `{display}`"))?;
    CommandResult::finish(display, &output)
}

/// `/run/user/<uid>` of `user`, when it exists.
fn user_runtime_dir(user: &str) -> Option<PathBuf> {
    let uid = nix::unistd::User::from_name(user).ok().flatten()?.uid;
    Some(super::apps_account::runtime_dir(uid.as_raw())).filter(|dir| dir.is_dir())
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
    if dry_run {
        return Ok(CommandResult::planned(display));
    }
    let (output, written) = output_with_timeout(Command::new(program).args(args), Some(input))
        .with_context(|| format!("failed to run `{program}`"))?;
    let result = CommandResult::finish(display, &output)?;
    written.with_context(|| format!("failed to write to `{}`", result.command))?;
    Ok(result)
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
        let context_type = positional("context_type", context_type)?;
        let pattern = positional("path_pattern", &pattern)?;
        let fcontext = |verb| {
            run_dry(
                "semanage",
                ["fcontext", verb, "-t", context_type, pattern],
                dry_run,
            )
        };
        // `-a` refuses a pattern that already has a local rule (the second
        // `apps.update` with the same options); `-m` changes that rule.
        let result = match fcontext("-a") {
            Err(_) if !dry_run => fcontext("-m")?,
            result => result?,
        };
        operations.push(json!(result));
    }

    if let Some(path) = path.as_deref() {
        let mut args = Vec::new();
        args.extend(options.recursive.then_some("-R"));
        args.extend_from_slice(&["-v", positional("path", path)?]);
        operations.push(run_dry("restorecon", &args, dry_run)?.into_json());
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
    Ok(vec![run_dry("restorecon", &args, dry_run)?.into_json()])
}

/// Whether `systemctl is-enabled` reports `unit` as `enabled`.
#[must_use]
pub fn unit_enabled(unit: &str) -> bool {
    run("systemctl", ["is-enabled", unit]).is_ok_and(|result| result.stdout.trim() == "enabled")
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

/// [`safe_join`] `relative` onto `base`, also refusing a path that passes
/// through a symlink below `base`, so a link planted in a managed directory
/// is never followed.
///
/// # Errors
/// Fails when `relative` escapes `base` or a component is a symlink.
pub fn resolve_under(base: &Path, relative: &str) -> Result<PathBuf> {
    let path = safe_join(base, relative)?;
    let mut current = base.to_path_buf();
    for component in Path::new(relative).components() {
        if let Component::Normal(component) = component {
            current.push(component);
            if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.is_symlink()) {
                bail!("managed path `{relative}` contains a symlink");
            }
        }
    }
    Ok(path)
}

/// Remove `relative` under `base` (see [`resolve_under`]) unless `dry_run`;
/// a missing file is not an error. Returns its path.
///
/// # Errors
/// Fails when the path is refused or the file cannot be removed.
pub fn remove_under(base: &Path, relative: &str, dry_run: bool) -> Result<PathBuf> {
    let path = resolve_under(base, relative)?;
    if !dry_run {
        crate::auth::store::remove_if_exists(&path)?;
    }
    Ok(path)
}

/// Atomically write `contents` to `relative` under `base` with `mode`.
///
/// Parent directories are created for nested paths. The path must stay inside
/// `base` and contain no symlink, so a planted link is never followed.
/// Nothing is written on a dry run; the path is returned either way.
///
/// # Errors
/// Fails when the path escapes `base` or contains a symlink, or the write
/// fails.
pub fn write_under(
    base: &Path,
    relative: &str,
    contents: &[u8],
    mode: u32,
    dry_run: bool,
) -> Result<PathBuf> {
    let path = resolve_under(base, relative)?;
    if !dry_run {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create `{}`", parent.display()))?;
        }
        crate::auth::store::replace(&path, contents, mode)?;
    }
    Ok(path)
}

/// Render a command and its args as a single space-joined display string.
/// Used both for dry-run previews and for error messages (`` `foo bar` failed ``).
#[must_use]
pub fn command_display<I: IntoIterator<Item = S>, S: std::fmt::Display, P: std::fmt::Display>(
    program: P,
    args: I,
) -> String {
    use std::fmt::Write as _;
    let mut display = program.to_string();
    for arg in args {
        write!(display, " {arg}").expect("writing to a String cannot fail");
    }
    display
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
        assert!(
            !error.contains("hunter2") && !error.contains("cat"),
            "{error}"
        );

        let result =
            run_command_with_input("definitely-not-a-real-command", &[], b"x", display(), true)
                .unwrap();
        assert!(result.dry_run);
        assert_eq!(result.command, "cat <secret>");
    }

    #[test]
    fn dry_run_command_does_not_execute() {
        let result = run_dry("definitely-not-a-real-command", ["arg"], true).unwrap();
        assert_eq!(result.command, "definitely-not-a-real-command arg");
        assert!(result.dry_run);
        assert_eq!(result.status, None);
        assert_eq!(
            result.clone().into_json(),
            json!({
                "command": "definitely-not-a-real-command arg",
                "status": null,
                "stdout": "",
                "stderr": "",
                "dry_run": true,
            })
        );
        // A dry run has no stdout to parse.
        let error = result.into_json_stdout().unwrap_err().to_string();
        assert_eq!(error, "failed to parse command stdout as JSON");
    }

    #[test]
    fn command_result_json_stdout_adds_data() {
        let result = CommandResult {
            command: "tool --json".into(),
            status: Some(0),
            stdout: r#"{"a":1}"#.into(),
            stderr: String::new(),
            dry_run: false,
        };
        assert_eq!(
            result.into_json_stdout().unwrap(),
            json!({
                "command": "tool --json",
                "status": 0,
                "stdout": r#"{"a":1}"#,
                "stderr": "",
                "dry_run": false,
                "data": { "a": 1 },
            })
        );
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
