use serde_json::json;

use crate::prelude::*;

use std::collections::BTreeMap;

use super::apps_account::APPS_USER;
use super::{AgentCommand, AgentResponse};

/// Registry of modules that the dispatcher routes commands to.
///
/// Built via [`Dispatcher::new`] + [`Dispatcher::with_module`] (or
/// [`Dispatcher::full`] for the
/// feature-gated default set). The `BTreeMap` keeps module iteration
/// deterministic — `agent.capabilities` lists modules in name order, which
/// makes dashboard diffs stable.
#[derive(Default)]
pub struct Dispatcher {
    modules: BTreeMap<String, Box<dyn Mod>>,
}

impl Dispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Create a new [`Dispatcher`] with all available modules.
    ///
    /// Use `--all-features` during compilation to actually enable all the modules.
    /// This only includes modules available during compile time, according to the feature set.
    #[must_use]
    pub fn full() -> Self {
        let mut dispatcher = Self::default();
        super::modules::register_all(&mut dispatcher);
        dispatcher
    }

    /// Builder-style registration: `Dispatcher::new().with_module(Foo).with_module(Bar)`.
    #[must_use]
    pub fn with_module<M: Mod + 'static>(mut self, module: M) -> Self {
        self.register(module);
        self
    }

    /// Register a module under its `name()`. A later registration with the
    /// same name replaces the earlier one.
    pub fn register<M: Mod + 'static>(&mut self, module: M) {
        self.modules
            .insert(module.name().to_owned(), Box::new(module));
    }

    /// Dispatch one command: route it to the matching module, or to the
    /// built-in `agent.capabilities` action. Any error becomes an
    /// `AgentResponse::error` with the same command `id` — the caller always
    /// gets a well-formed response, never a panic.
    #[must_use]
    pub fn dispatch(&self, mut command: AgentCommand) -> AgentResponse {
        match self.try_dispatch(&mut command) {
            Ok(payload) => AgentResponse::ok(command.id, payload),
            Err(error) => AgentResponse::error(command.id, error.to_string()),
        }
    }

    /// Snapshot of every module's [`ModuleInfo`]. Used to answer
    /// `agent.capabilities`; also useful for diagnostics and tests.
    #[must_use]
    pub fn capabilities(&self) -> Vec<ModuleInfo> {
        self.modules.values().map(|module| module.info()).collect()
    }

    fn try_dispatch(&self, command: &mut AgentCommand) -> Result<Value> {
        command.validate()?;
        // `agent.capabilities` is reserved at the dispatcher level rather than
        // living in a fake `agent` module, so it always reports the *actually
        // registered* module set even if a custom dispatcher was built.
        if command.requests_capabilities() {
            return Ok(json!({ "modules": self.capabilities() }));
        }

        let Some(module) = self.modules.get(&command.module) else {
            bail!("unknown module `{}`", command.module);
        };

        if let Some(response) = module.metadata(&command.action, &command.payload) {
            return Ok(response);
        }
        let run_as = RunAs::take(&mut command.payload)?.unwrap_or_else(|| module.default_run_as());
        // The command is owned: hand the (possibly large) payload over
        // instead of copying it.
        let payload = std::mem::take(&mut command.payload);
        let action = command.action.as_str();
        match run_as {
            RunAs::User => module.handle(action, payload, command.user()),
            RunAs::Apps => module.handle(action, payload, Some(APPS_USER)),
            RunAs::Root => module.handle(action, payload, None),
            RunAs::Both => {
                let user = command
                    .user()
                    .context("`run_as: both` needs a signed-in user")?;
                ensure!(
                    !module.info().is_privileged(action),
                    "{}.{action} always runs as root; `run_as: both` is for reads",
                    command.module
                );
                let outcome = |result: Result<Value>| match result {
                    Ok(result) => json!({ "ok": true, "result": result }),
                    Err(error) => json!({ "ok": false, "error": format!("{error:#}") }),
                };
                Ok(json!({
                    "user": outcome(module.handle(action, payload.clone(), Some(user))),
                    "root": outcome(module.handle(action, payload, None)),
                }))
            }
        }
    }
}

/// Who host commands of an action run as, from the payload's optional
/// `run_as` field (removed before the module sees the payload), or the
/// module's [`Mod::default_run_as`] without one.
///
/// Unprivileged actions run as the signed-in user by default, so a user sees
/// their own containers or VMs; `apps` runs them as the
/// [`APPS_USER`] account that user apps run under (the default of
/// `podman`), `root` shows the host's, and `both` runs the action twice and
/// returns `{user, root}`, each `{ok, result}` or `{ok, error}`. Privileged
/// actions always run as root. `root` and `both` are administrator-only (see
/// `auth::authz::admin_only_field`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunAs {
    #[default]
    User,
    Apps,
    Root,
    Both,
}

impl RunAs {
    /// The payload field naming it.
    pub const FIELD: &str = "run_as";

    /// Remove the field from `payload`; `None` when it has none.
    fn take(payload: &mut Value) -> Result<Option<Self>> {
        let Some(value) = payload
            .as_object_mut()
            .and_then(|object| object.remove(Self::FIELD))
        else {
            return Ok(None);
        };
        serde_json::from_value(value)
            .map(Some)
            .context("`run_as` must be `user`, `apps`, `root` or `both`")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    struct Echo;

    impl Mod for Echo {
        fn info(&self) -> ModuleInfo {
            ModuleInfo {
                name: "echo",
                feature: "test",
                description: "Test echo module",
                status: super::super::module_support::ModuleStatus::Available,
                actions: &["ping", "wipe"],
                privileged_actions: &["wipe"],
            }
        }

        fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
            if user == Some("nobody") {
                bail!("permission denied");
            }
            Ok(json!({ "action": action, "payload": payload, "user": user }))
        }
    }

    #[test]
    fn routes_commands_to_named_modules() {
        let dispatcher = Dispatcher::new().with_module(Echo);
        let response = dispatcher.dispatch(AgentCommand {
            id: "cmd-1".into(),
            module: "echo".into(),
            action: "ping".into(),
            payload: json!({ "value": 42 }),
            signature: None,
            user: None,
        });

        assert!(response.ok);
        assert_eq!(
            response.payload,
            Some(json!({ "action": "ping", "payload": { "value": 42 }, "user": null }))
        );
    }

    fn as_alice(action: &str, payload: Value, user: &str) -> AgentResponse {
        Dispatcher::new().with_module(Echo).dispatch(AgentCommand {
            id: "cmd".into(),
            module: "echo".into(),
            action: action.into(),
            payload,
            signature: None,
            user: Some(user.into()),
        })
    }

    #[test]
    fn run_as_picks_the_user_root_or_both() {
        let user = as_alice("ping", json!({ "x": 1 }), "alice");
        assert_eq!(user.payload.unwrap()["user"], "alice");

        let root = as_alice("ping", json!({ "x": 1, "run_as": "root" }), "alice");
        let root = root.payload.unwrap();
        assert!(root["user"].is_null());
        // The module never sees `run_as`.
        assert_eq!(root["payload"], json!({ "x": 1 }));

        let both = as_alice("ping", json!({ "run_as": "both" }), "nobody")
            .payload
            .unwrap();
        assert_eq!(both["user"]["ok"], false);
        assert_eq!(both["user"]["error"], "permission denied");
        assert_eq!(both["root"]["ok"], true);
        assert!(both["root"]["result"]["user"].is_null());

        assert!(!as_alice("wipe", json!({ "run_as": "both" }), "alice").ok);
        assert!(!as_alice("ping", json!({ "run_as": "admin" }), "alice").ok);

        let apps = as_alice("ping", json!({ "run_as": "apps" }), "alice");
        assert_eq!(apps.payload.unwrap()["user"], "ultramarine-apps");
    }

    /// Echo, defaulting to the apps account like `podman`.
    struct AppsEcho;

    impl Mod for AppsEcho {
        fn info(&self) -> ModuleInfo {
            ModuleInfo {
                name: "apps_echo",
                ..Echo.info()
            }
        }

        fn default_run_as(&self) -> RunAs {
            RunAs::Apps
        }

        fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
            Echo.handle(action, payload, user)
        }
    }

    #[test]
    fn modules_pick_their_default_run_as() {
        let dispatcher = Dispatcher::new().with_module(AppsEcho);
        let run = |payload: Value, user: Option<&str>| {
            dispatcher
                .dispatch(AgentCommand {
                    id: "cmd".into(),
                    module: "apps_echo".into(),
                    action: "ping".into(),
                    payload,
                    signature: None,
                    user: user.map(str::to_owned),
                })
                .payload
                .unwrap()["user"]
                .clone()
        };
        // Without `run_as`, as the apps account, signed in or not.
        assert_eq!(run(json!({}), Some("alice")), "ultramarine-apps");
        assert_eq!(run(json!({}), None), "ultramarine-apps");
        assert_eq!(run(json!({ "run_as": "user" }), Some("alice")), "alice");
        assert!(run(json!({ "run_as": "root" }), Some("alice")).is_null());
    }
}
