//! Kameo actor wrapping the [`Dispatcher`] so transports can handle commands
//! concurrently without exposing a `&mut`.
//!
//! The actor is the unit of concurrency: each transport (vsock, WSS)
//! owns an [`ActorRef<AgentBackend>`] and sends [`DispatchCommand`]s to it.
//! Kameo serializes `handle` calls on the actor's task, so the dispatcher's
//! `&self`-only API stays sound no matter how many in-flight requests arrive.
//! A long-running module action can't starve another transport's request
//! because each `ask` is awaited independently by the caller.

use anyhow::Result;
use kameo::{
    actor::{Actor, ActorRef, Spawn},
    error::Infallible,
    message::{Context, Message},
};

use super::{AgentCommand, AgentResponse, Dispatcher, messages::DispatchCommand};

/// Kameo actor that owns the [`Dispatcher`] and handles [`DispatchCommand`]s.
///
/// Constructed via [`AgentBackend::with_default_modules`] (default feature set)
/// or [`AgentBackend::new`] (custom dispatcher). Transports receive an
/// [`ActorRef<Self>`] and drive it through `ask(DispatchCommand(...))`.
pub struct AgentBackend {
    dispatcher: Dispatcher,
}

impl AgentBackend {
    /// Wrap a pre-built dispatcher. Use this when a transport needs a
    /// non-default module set.
    #[must_use]
    pub const fn new(dispatcher: Dispatcher) -> Self {
        Self { dispatcher }
    }

    /// Build a backend with the default feature-gated module set
    /// ([`modules::default_dispatcher`]).
    #[must_use]
    pub fn with_default_modules() -> Self {
        Self::new(Dispatcher::full())
    }

    /// Spawn an actor backed by the default module set and return a handle
    /// the caller can `ask` from any async task.
    #[must_use]
    pub fn spawn_default() -> ActorRef<Self> {
        Self::spawn(Dispatcher::full())
    }
}

impl Actor for AgentBackend {
    /// The dispatcher is passed in at spawn time (rather than built inside
    /// `on_start`) so callers can configure the module set before the actor
    /// owns it.
    type Args = Dispatcher;
    type Error = Infallible;

    fn on_start(
        args: Self::Args,
        _actor_ref: ActorRef<Self>,
    ) -> impl Future<Output = Result<Self, Self::Error>> {
        std::future::ready(Ok(Self::new(args)))
    }
}

impl Message<DispatchCommand> for AgentBackend {
    type Reply = Result<AgentResponse>;

    fn handle(
        &mut self,
        DispatchCommand(command): DispatchCommand,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> impl Future<Output = Self::Reply> {
        // Dispatcher::dispatch takes &self, so the actor's `&mut self` here is
        // only used by Kameo to serialize messages — the dispatcher itself
        // stays freely shareable.
        std::future::ready(Ok(self.dispatcher.dispatch(command)))
    }
}

/// Convenience for the `agent-dispatch` CLI.
///
/// Spawns a one-shot backend, dispatches a single command, and returns the
/// response. The actor is dropped when the returned future completes; the
/// spawned task won't leak because nothing else holds the `ActorRef`.
///
/// # Errors
/// See [`ActorRef::ask`].
pub async fn dispatch_with_default_backend(command: AgentCommand) -> Result<AgentResponse> {
    let backend = AgentBackend::spawn_default();
    backend
        .ask(DispatchCommand(command))
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
}
