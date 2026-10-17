//! The agent: a feature-gated command dispatcher plus the transports that
//! expose it to a dashboard or control plane.
//!
//! Architecture at a glance:
//!
//! - [`Dispatcher`] routes an [`AgentCommand`] `{module, action, payload}`
//!   envelope to the matching [`AgentModule`] and returns an [`AgentResponse`].
//! - [`modules`] holds one `AgentModule` implementation per host-management
//!   surface (settings, files, services, quadlets, recipes, …), each gated by
//!   a Cargo feature so installs only ship what they need.
//! - [`module_support`] provides the shared plumbing every module uses:
//!   `ModuleInfo` metadata, the `capabilities`/`plan` meta-actions, the dry-run
//!   command runner, and the shared SELinux-labeling helper.
//! - [`backend`] wraps the dispatcher in a Kameo actor so transports can handle
//!   commands concurrently without sharing a `&mut Dispatcher`.
//! - Transports — [`local_socket`], [`vsock`] and [`websocket`] — feed the same
//!   envelope shape into the same backend. [`local_socket`] is the only
//!   listener in production; [`transport`] holds the shared endpoint-parsing
//!   config.

pub mod backend;
pub mod command;
pub mod config;
pub mod crypto;
pub mod dispatcher;
pub mod identity;
pub mod local_socket;
pub mod messages;
pub mod module_support;
pub mod modules;
pub mod protocol;
pub mod queue;
pub mod remote;
pub mod transport;
pub mod verify_password;
pub mod vsock;
pub mod websocket;
pub mod websocket_server;

pub use backend::AgentBackend;
pub use command::{AgentCommand, AgentResponse};
pub use dispatcher::Dispatcher;
pub use messages::DispatchCommand;
