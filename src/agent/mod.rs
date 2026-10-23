//! The agent: a feature-gated command dispatcher plus the transports that
//! expose it to a dashboard or control plane.
//!
//! Architecture at a glance:
//!
//! - [`Dispatcher`] routes an [`AgentCommand`] `{module, action, payload}`
//!   envelope to the matching [`Mod`](modules::Mod) and returns an [`AgentResponse`].
//! - [`modules`] holds one [`Mod`](modules::Mod) implementation per host-management
//!   surface (settings, files, services, quadlets, recipes, …), each gated by
//!   a Cargo feature so installs only ship what they need.
//! - [`module_support`] provides the shared plumbing every module uses:
//!   `ModuleInfo` metadata, the `capabilities`/`plan` meta-actions, the dry-run
//!   command runner, and the shared SELinux-labeling helper.
//! - [`queue`] runs commands from every transport one at a time on the
//!   blocking pool.
//! - Transports — [`local_socket`] and [`websocket`] — feed the same envelope
//!   shape into the same queue. [`local_socket`] is the only listener in
//!   production; the development-only `dev_listener` serves the same session
//!   protocol on loopback TCP. [`transport`] holds the outbound endpoint
//!   config.

pub mod apps_account;
pub mod command;
pub mod config;
#[cfg(feature = "dev-listener")]
pub mod dev_listener;
pub mod dispatcher;
pub mod identity;
pub mod local_protocol;
pub mod local_socket;
pub mod module_support;
pub mod modules;
pub mod peer;
pub mod queue;
pub mod remote;
pub mod transport;
pub mod websocket;

pub use command::{AgentCommand, AgentResponse};
pub use dispatcher::Dispatcher;
