//! Bounded transport-to-dispatch queue.
//!
//! Kameo serializes [`super::AgentBackend`] messages, but transport tasks could
//! previously accumulate without an explicit admission limit. This queue adds
//! backpressure before commands reach the actor: callers receive `QueueFull`
//! rather than holding unbounded sockets/tasks while a slow host operation runs.
//!
//! The initial policy intentionally serializes all dispatched commands. This is
//! conservative for host mutations (users, systemd, storage, Quadlets) and
//! avoids assuming a read operation is harmless on every platform. A future
//! scheduler can split verified read-only operations into a bounded concurrent
//! lane without weakening mutation ordering.

use crate::prelude::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use kameo::actor::ActorRef;
use tokio::sync::{mpsc, oneshot};

/// Maximum number of commands waiting or being admitted to the dispatcher by
/// default. Transports should report a retryable queue-full error instead of
/// retaining arbitrary numbers of client tasks.
pub const DEFAULT_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueMetrics {
    pub capacity: usize,
    pub pending: usize,
}

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
    pending: Arc<AtomicUsize>,
    capacity: usize,
}

impl DispatchQueue {
    /// Spawn a new dispatcher in the tokio global scope.
    ///
    /// # Panics
    /// Dispatch queue capacity must be positive.
    #[must_use]
    pub fn spawn(backend: ActorRef<AgentBackend>, capacity: usize) -> Self {
        assert!(capacity > 0, "dispatch queue capacity must be positive");
        let (sender, mut receiver) = mpsc::channel::<QueuedCommand>(capacity);
        let pending = Arc::new(AtomicUsize::new(0));
        let worker_pending = Arc::clone(&pending);

        tokio::spawn(async move {
            while let Some(queued) = receiver.recv().await {
                let response = backend.ask(DispatchCommand(queued.command)).await;
                let response = response.unwrap_or_else(|error| {
                    AgentResponse::error("dispatch-error", error.to_string())
                });
                // The receiver may have disconnected after timing out. The
                // command already ran, so dropping this response is correct;
                // callers must use command IDs for idempotency/reconciliation.
                _ = queued.reply.send(response);
                worker_pending.fetch_sub(1, Ordering::Release);
            }
        });

        Self {
            sender,
            pending,
            capacity,
        }
    }

    /// Admit one command without waiting for capacity. This is deliberate:
    /// network transports need deterministic backpressure instead of spawning
    /// unbounded waiting futures for a controller that outpaces the host.
    pub async fn dispatch(&self, command: AgentCommand) -> Result<AgentResponse, QueueError> {
        let (reply, receiver) = oneshot::channel();
        let queued = QueuedCommand { command, reply };
        // Increment before making the item visible to the worker. Otherwise a
        // fast worker could decrement first and underflow the metric.
        self.pending.fetch_add(1, Ordering::Release);
        (self.sender.try_send(queued))
            .inspect_err(|_| _ = self.pending.fetch_sub(1, Ordering::Release))?;
        receiver.await.map_err(|_| QueueError::Closed)
    }

    #[must_use]
    pub fn metrics(&self) -> QueueMetrics {
        QueueMetrics {
            capacity: self.capacity,
            pending: self.pending.load(Ordering::Acquire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queue_rejects_when_admission_capacity_is_exhausted() {
        let backend = AgentBackend::spawn_default();
        let queue = DispatchQueue::spawn(backend, 1);
        // Suspend the worker by filling the channel before yielding. The second
        // non-blocking admission must fail rather than creating another waiter.
        let (reply, _receiver) = oneshot::channel();
        queue.pending.fetch_add(1, Ordering::Release);
        queue
            .sender
            .try_send(QueuedCommand {
                command: AgentCommand {
                    id: "queued".into(),
                    module: "settings".into(),
                    action: "get_system".into(),
                    payload: Value::Null,
                    signature: None,
                    user: None,
                },
                reply,
            })
            .unwrap();
        let result = queue
            .dispatch(AgentCommand {
                id: "queue-full".into(),
                module: "settings".into(),
                action: "get_system".into(),
                payload: jsonf! {},
                signature: None,
                user: None,
            })
            .await;
        assert_eq!(result, Err(QueueError::Full));
    }

    #[tokio::test]
    async fn queue_reports_metrics_and_dispatches() {
        let backend = AgentBackend::spawn_default();
        let queue = DispatchQueue::spawn(backend, 1);
        assert_eq!(queue.metrics().capacity, 1);
        assert_eq!(queue.metrics().pending, 0);

        let response = queue
            .dispatch(AgentCommand {
                id: "queue-settings".into(),
                module: "settings".into(),
                action: "get_system".into(),
                payload: Value::Null,
                signature: None,
                user: None,
            })
            .await
            .unwrap();
        assert!(response.ok);
        assert_eq!(queue.metrics().pending, 0);
    }
}
