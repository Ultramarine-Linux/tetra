use super::AgentCommand;

/// Wrapper around [`AgentCommand`] used as the message type for the Kameo
/// `AgentBackend` actor.
///
/// Kameo's `Message<…>` impl needs a concrete type to dispatch on, so the
/// command is newtyped here rather than implementing `Message<AgentCommand>`
/// directly (which would collide with other potential blanket impls).
#[derive(Debug, Clone)]
pub struct DispatchCommand(pub AgentCommand);
