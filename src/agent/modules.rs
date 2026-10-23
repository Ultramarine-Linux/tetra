// `settings` is always compiled — it provides the always-available `get_system`
// action that other modules and the dashboard rely on for host identification.
pub mod settings;
pub use crate::prelude::*;
pub use settings::SettingsModule;

macro_rules! modules {
    ($($m:ident: $feature:literal => $Module:ident),+ $(,)?) => {
        $(
            #[cfg(feature = $feature)]
            pub mod $m;
            #[cfg(feature = $feature)]
            pub use $m::$Module;
        )+
        /// Register every module compiled into this build.
        pub fn register_all(dispatcher: &mut super::Dispatcher) {
            dispatcher.register(SettingsModule);
            $(
                #[cfg(feature = $feature)]
                dispatcher.register($Module);
            )+
        }
    };
}

modules![
    apps: "apps" => AppsModule,
    files: "files" => FilesModule,
    network: "network" => NetworkModule,
    nfs: "nfs" => NfsModule,
    podman: "podman" => PodmanModule,
    power: "power" => PowerModule,
    quadlets: "quadlets" => QuadletsModule,
    recipes: "recipes" => RecipesModule,
    remote_access: "remote-access" => RemoteAccessModule,
    reverse_proxy: "reverse-proxy" => ReverseProxyModule,
    samba: "samba" => SambaModule,
    selinux: "selinux" => SelinuxModule,
    services: "services" => ServicesModule,
    storage: "storage" => StorageModule,
    updates: "updates" => UpdatesModule,
    users: "users" => UsersModule,
    virtual_machines: "virtual-machines" => VirtualMachinesModule,
];

/// A single host-management surface exposed to the dashboard.
///
/// Each module owns one slice of host state (settings, files, services,
/// quadlets, …). The [`Dispatcher`](super::Dispatcher) looks up a module by name and hands the
/// command's `action` and `payload` to its `handle` method.
///
/// Modules are stateless: `handle` takes `&self`, so the same module can be
/// invoked concurrently from multiple transport tasks. State lives in the
/// host (systemd, the filesystem, etc.), not in the module.
pub trait Mod: Send + Sync {
    /// Static metadata describing this module to the dashboard: name, feature
    /// flag, description, status, and the actions it supports.
    fn info(&self) -> ModuleInfo;

    /// Convenience defaulting `name` to the name in [`info`](Self::info).
    /// Overridable in case a module wants to register under an alias without
    /// changing its reported metadata.
    fn name(&self) -> &'static str {
        self.info().name
    }

    /// Answer the shared `capabilities`/`plan` meta-actions, which the
    /// [`Dispatcher`](super::Dispatcher) asks before [`handle`](Self::handle). `None` for every
    /// other action.
    fn metadata(&self, action: &str, payload: &Value) -> Option<Value> {
        self.info().metadata_response(action, payload)
    }

    /// Handle one module-specific action.
    ///
    /// - `action` is the command's `action` field
    /// - `payload` is the command's `payload` (already parsed from JSON by the transport)
    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value>;
}

pub trait Act: Deserialize<'static> {
    // fn is_priviledged(&self) -> bool;
    fn handle(self, user: Option<&str>) -> Result<Value>;
}

/// Declares the typed actions supported by a module.
///
/// The macro generates one `Deserialize` payload struct for each action and an
/// enum named by `$Action` that dispatches the decoded payload to its action
/// handler. Action bodies return `anyhow::Result<serde_json::Value>` and may
/// access the payload through `$payload` and the authenticated user through
/// `$user`.
///
/// # Syntax
///
/// ```text
/// actions!(Action [payload user] => {
///     List => { /* return a Result<Value> */ },
///     Read: Request => { /* use payload.path */ },
///     Remove { name: String } => { /* use payload.name */ },
/// });
/// ```
///
/// An action without a payload uses an empty struct, which accepts any
/// object. A typed action may use a named struct, tuple payload, or any type
/// that implements `Deserialize`. The generated action enum is deserialized
/// from an object whose key is the action name in snake case, matching the
/// wire protocol; an omitted payload (`null`) is read as `{}`, so actions
/// whose fields all have defaults accept it (see
/// [`parse_action`](super::module_support::parse_action)).
#[macro_export]
macro_rules! actions {
    ($Action:ident [$payload:ident $user:ident] => {$($inner:tt)*}) => {
        $crate::actions!(@[$payload $user $Action]{$($inner)*,}[]);
    };
    (@[$payload:ident $user:ident $Action:ident]{$a:ident {$($struct:tt)*} => $body:expr, $($rest:tt)*}[$($done:ident)*]) => {
        #[derive(Debug, ::serde::Deserialize)]
        struct $a {$($struct)*}
        impl $crate::prelude::Act for $a {
            // fn is_priviledged(&self) -> bool { false }
            fn handle(self, user: Option<&str>) -> Result<Value> {
                #[allow(unused_variables)]
                let ($user, $payload) = (user, self);
                $body
            }
        }
        $crate::actions!(@[$payload $user $Action]{$($rest)*}[$($done)* $a]);
    };
    (@[$payload:ident $user:ident $Action:ident]{$a:ident => $body:expr, $($rest:tt)*}[$($done:ident)*]) => {
        // Takes no payload: any object (or `null`, see `parse_action`).
        #[derive(Debug, ::serde::Deserialize)]
        struct $a {}
        impl $crate::prelude::Act for $a {
            // fn is_priviledged(&self) -> bool { false }
            fn handle(self, user: Option<&str>) -> Result<Value> {
                #[allow(unused_variables)]
                let ($user, $payload) = (user, self);
                $body
            }
        }
        $crate::actions!(@[$payload $user $Action]{$($rest)*}[$($done)* $a]);
    };
    (@[$payload:ident $user:ident $Action:ident]{$a:ident: $t:ty => $body:expr, $($rest:tt)*}[$($done:ident)*]) => {
        #[derive(Debug, ::serde::Deserialize)]
        struct $a($t);
        impl $crate::prelude::Act for $a {
            // fn is_priviledged(&self) -> bool { false }
            fn handle(self, user: Option<&str>) -> Result<Value> {
                #[allow(unused_variables)]
                let ($user, $payload) = (user, self.0);
                $body
            }
        }
        $crate::actions!(@[$payload $user $Action]{$($rest)*}[$($done)* $a]);
    };
    (@[$payload:ident $user:ident $Action:ident]{$(,)?}[$($done:ident)*]) => {
        #[derive(Debug, ::serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum $Action { $( $done($done), )* }
        impl $crate::prelude::Act for $Action {
            // fn is_priviledged(&self) -> bool { match self {
            //     $( Self::$done(a) => a.is_priviledged(), )*
            // }}
            fn handle(self, user: Option<&str>) -> Result<::serde_json::Value> { match self {
                $( Self::$done(a) => a.handle(user), )*
            }}
        }
        impl $Action {
            fn from_payload(action: &str, payload: Value) -> Result<impl Act> {
                $crate::agent::module_support::parse_action::<$Action>(action, payload)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    actions!(Action [payload user] => {
        Ping => Ok(json!("pong")),
        Echo { value: i64 } => Ok(json!(payload.value)),
        Stop {
            #[serde(default)]
            dry_run: bool,
        } => Ok(json!(payload.dry_run)),
    });

    #[test]
    fn payload_less_actions_take_null_or_an_object() {
        for payload in [Value::Null, json!({}), json!({ "x": 1 })] {
            let response = Action::from_payload("ping", payload).unwrap().handle(None);
            assert_eq!(response.unwrap(), "pong");
        }
        assert!(Action::from_payload("ping", json!("")).is_err());
        assert!(Action::from_payload("ping", json!([1])).is_err());
        // A payload whose fields all have defaults may be left out.
        let response = Action::from_payload("stop", Value::Null)
            .unwrap()
            .handle(None);
        assert_eq!(response.unwrap(), false);
        assert!(Action::from_payload("echo", Value::Null).is_err());
        let response = Action::from_payload("echo", json!({ "value": 7 }))
            .unwrap()
            .handle(None);
        assert_eq!(response.unwrap(), 7);
    }
}
