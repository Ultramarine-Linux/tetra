use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A command envelope dispatched to the agent.
///
/// This is the single shape every transport (vsock, WSS) and the local
/// `agent-dispatch` CLI all accept. The [`Dispatcher`](super::Dispatcher) routes
/// on `module` + `action` and hands `payload` to the matching module's
/// `handle` method.
///
/// `id` is opaque to the agent — it's echoed back in the [`AgentResponse`] so
/// the controller can correlate requests and responses over async transports.
///
/// `signature` is reserved for future command signing. It is currently only
/// checked for emptiness (see [`Dispatcher::dispatch`](super::Dispatcher)); a
/// non-empty value is accepted but not yet verified against a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentCommand {
    pub id: String,
    pub module: String,
    pub action: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub signature: Option<String>,
    /// The host user to run unprivileged actions as. Set by the transport
    /// after session authentication; not part of the signed wire format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl AgentCommand {
    /// Reject malformed signature metadata before routing the command.
    ///
    /// Actual cryptographic verification is performed by authenticated
    /// transports, which have the session context required to verify it.
    ///
    /// # Errors
    /// Returns an error when a signature field is present but empty.
    pub fn validate(&self) -> Result<()> {
        if self.signature.as_deref() == Some("") {
            bail!("command signature cannot be empty");
        }

        Ok(())
    }

    /// Whether this is the dispatcher-owned capabilities query.
    #[must_use]
    pub fn requests_capabilities(&self) -> bool {
        self.module == "agent" && self.action == "capabilities"
    }

    /// Return the authenticated host user, if one was assigned by the transport.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }
}

/// The response to an [`AgentCommand`].
///
/// Exactly one of `payload` (success) or `error` (failure) is set; the
/// `skip_serializing_if` attributes keep the wire format compact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentResponse {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AgentResponse {
    /// Build a successful response carrying `payload`, echoing the command `id`.
    pub fn ok<S: Into<String>>(id: S, payload: Value) -> Self {
        Self {
            id: id.into(),
            ok: true,
            payload: Some(payload),
            error: None,
        }
    }

    /// Build an error response carrying a human-readable `error` message,
    /// echoing the command `id`.
    pub fn error<S: Into<String>, E: Into<String>>(id: S, error: E) -> Self {
        Self {
            id: id.into(),
            ok: false,
            payload: None,
            error: Some(error.into()),
        }
    }
}
