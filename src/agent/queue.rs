//! Bounded transport-to-dispatch queue.
//!
//! Transports admit commands without waiting: when the queue is full the
//! caller gets [`QueueError::Full`] instead of piling up sockets and tasks
//! while a slow host operation runs.
//!
//! One worker runs the commands one at a time. This is conservative for host
//! mutations (users, systemd, storage, Quadlets) and avoids assuming a read is
//! harmless on every platform. Each command runs on Tokio's blocking pool, so
//! a module that shells out or sleeps never stalls the async runtime, and a
//! module that panics fails only its own command.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use super::Dispatcher;
use crate::prelude::*;

/// Maximum number of commands waiting for the dispatcher by default.
/// Transports should report a retryable queue-full error instead of retaining
/// arbitrary numbers of client tasks.
pub const DEFAULT_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// The bounded queue is full. The caller may retry after backoff.
    Full,
    /// The worker stopped, typically because the process is shutting down.
    Closed,
}
impl<T> From<mpsc::error::TrySendError<T>> for QueueError {
    fn from(value: mpsc::error::TrySendError<T>) -> Self {
        match value {
            mpsc::error::TrySendError::Full(_) => Self::Full,
            mpsc::error::TrySendError::Closed(_) => Self::Closed,
        }
    }
}

struct QueuedCommand {
    command: AgentCommand,
    reply: oneshot::Sender<AgentResponse>,
}

#[derive(Clone)]
pub struct DispatchQueue {
    sender: mpsc::Sender<QueuedCommand>,
}

impl DispatchQueue {
    /// Spawn the worker for `dispatcher` on the current Tokio runtime.
    ///
    /// # Panics
    /// Dispatch queue capacity must be positive.
    #[must_use]
    pub fn spawn(dispatcher: Dispatcher, capacity: usize) -> Self {
        assert!(capacity > 0, "dispatch queue capacity must be positive");
        let (sender, mut receiver) = mpsc::channel::<QueuedCommand>(capacity);
        let dispatcher = Arc::new(dispatcher);
        tokio::spawn(async move {
            while let Some(QueuedCommand { command, reply }) = receiver.recv().await {
                let id = command.id.clone();
                let dispatcher = Arc::clone(&dispatcher);
                let response = tokio::task::spawn_blocking(move || dispatcher.dispatch(command))
                    .await
                    .unwrap_or_else(|error| {
                        AgentResponse::error(id, format!("dispatch failed: {error}"))
                    });
                // The receiver may have disconnected after timing out. The
                // command already ran, so dropping this response is correct;
                // callers must use command IDs for idempotency/reconciliation.
                _ = reply.send(response);
            }
        });
        Self { sender }
    }

    /// Admit one command without waiting for capacity. This is deliberate:
    /// network transports need deterministic backpressure instead of spawning
    /// unbounded waiting futures for a controller that outpaces the host.
    pub async fn dispatch(&self, command: AgentCommand) -> Result<AgentResponse, QueueError> {
        let (reply, receiver) = oneshot::channel();
        self.sender.try_send(QueuedCommand { command, reply })?;
        receiver.await.map_err(|_| QueueError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(id: &str) -> AgentCommand {
        AgentCommand {
            id: id.into(),
            module: "settings".into(),
            action: "get_system".into(),
            payload: Value::Null,
            signature: None,
            user: None,
        }
    }

    #[tokio::test]
    async fn queue_rejects_when_admission_capacity_is_exhausted() {
        let queue = DispatchQueue::spawn(Dispatcher::full(), 1);
        // Fill the channel before the worker gets to run. The second
        // non-blocking admission must fail rather than creating another waiter.
        let (reply, _receiver) = oneshot::channel();
        queue
            .sender
            .try_send(QueuedCommand {
                command: command("queued"),
                reply,
            })
            .unwrap();
        let result = queue.dispatch(command("queue-full")).await;
        assert_eq!(result, Err(QueueError::Full));
    }

    #[tokio::test]
    async fn queue_dispatches() {
        let queue = DispatchQueue::spawn(Dispatcher::full(), 1);
        let response = queue.dispatch(command("queue-settings")).await.unwrap();
        assert!(response.ok);
        assert_eq!(response.id, "queue-settings");
    }
}
