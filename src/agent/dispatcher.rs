use crate::prelude::*;

use std::collections::BTreeMap;

use super::{AgentCommand, AgentResponse};

/// Registry of modules that the dispatcher routes commands to.
///
/// Built via [`Dispatcher::new`] + [`Dispatcher::with_module`] (or
/// [`modules::default_dispatcher`](super::modules::default_dispatcher) for the
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
        Self {
            modules: super::modules::MODULES
                .entries()
                .map(|(&k, v)| (k.to_owned(), Box::new(v.clone()) as Box<dyn Mod>))
                .collect(),
        }
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
    pub fn dispatch(&self, command: AgentCommand) -> AgentResponse {
        match self.try_dispatch(&command) {
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

    fn try_dispatch(&self, command: &AgentCommand) -> Result<Value> {
        command.validate()?;
        // `agent.capabilities` is reserved at the dispatcher level rather than
        // living in a fake `agent` module, so it always reports the *actually
        // registered* module set even if a custom dispatcher was built.
        if command.requests_capabilities() {
            return Ok(jsonf! { "modules": self.capabilities() });
        }

        let Some(module) = self.modules.get(&command.module) else {
            bail!("unknown module `{}`", command.module);
        };

        module.handle(&command.action, command.payload.clone(), command.user())
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
                actions: &["ping"],
                privileged_actions: &[],
            }
        }

        fn handle(&self, action: &str, payload: Value, _user: Option<&str>) -> Result<Value> {
            Ok(json!({ "action": action, "payload": payload }))
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
            Some(json!({ "action": "ping", "payload": { "value": 42 } }))
        );
    }
}
