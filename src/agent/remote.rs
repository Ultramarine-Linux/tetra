//! Runtime gate for the outbound control-plane connection (`remote.enabled`).
//!
//! The desired connection lives in a [`watch`] channel: `None` means remote
//! control is off. [`supervise`] runs the connection only while the channel
//! holds `Some`, and drops it (closing the socket) as soon as the value
//! changes, so disabling remote control at runtime cuts any live session.

use std::{
    future::Future,
    path::{Path, PathBuf},
};

use anyhow::Result;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::watch,
};

use super::{
    config::RuntimeConfig,
    queue::DispatchQueue,
    websocket::{self, WebSocketAgentConfig},
};
use crate::{auth::audit::AuditLog, enrollment::store::Enrollment};

/// Run the outbound connection whenever `settings` holds one, sharing `queue`
/// with the local transports and recording remote actions in `audit`. Returns
/// when the sender is dropped.
pub async fn supervise(
    settings: watch::Receiver<Option<WebSocketAgentConfig>>,
    queue: DispatchQueue,
    audit: AuditLog,
) {
    supervise_with(settings, |config| {
        websocket::run_with_queue(config, queue.clone(), audit.clone())
    })
    .await;
}

/// [`supervise`] with the connection future supplied by the caller.
async fn supervise_with<T, F, Fut>(mut settings: watch::Receiver<Option<T>>, mut connect: F)
where
    T: Clone + Send + Sync,
    F: FnMut(T) -> Fut + Send,
    Fut: Future<Output = Result<()>> + Send,
{
    loop {
        let current = settings.borrow_and_update().clone();
        if let Some(config) = current {
            eprintln!("remote control enabled; connecting to the control plane");
            tokio::select! {
                result = connect(config) => match result {
                    Ok(()) => eprintln!("remote control session ended"),
                    Err(error) => eprintln!("remote control session failed: {error:?}"),
                },
                // Dropping the connection future closes the socket.
                _ = settings.changed() => {
                    eprintln!("remote control settings changed; dropping the current session");
                    continue;
                }
            }
        } else {
            eprintln!("remote control disabled; not connecting out");
        }
        if settings.changed().await.is_err() {
            return;
        }
    }
}

/// Re-read the runtime config on every `SIGHUP` and publish the connection it
/// describes. Publishes only when the result differs, so a reload that leaves
/// the remote settings alone keeps the live session.
pub async fn reload_on_hangup<F>(
    path: PathBuf,
    sender: watch::Sender<Option<WebSocketAgentConfig>>,
    select: F,
) -> Result<()>
where
    F: Fn(&RuntimeConfig) -> Option<WebSocketAgentConfig>,
{
    let mut hangup = signal(SignalKind::hangup())?;
    while hangup.recv().await.is_some() {
        eprintln!("reloading {}", path.display());
        let next = select(&RuntimeConfig::load_or_disabled(&path));
        sender.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }
    Ok(())
}

/// The connection the daemon should run for `config` and the enrollment in
/// `enrollment_dir`, logging (and treating as disabled) a remote section that
/// is enabled but incomplete or an unreadable enrollment.
#[must_use]
pub fn connection_from(
    config: &RuntimeConfig,
    enrollment_dir: &Path,
) -> Option<WebSocketAgentConfig> {
    if !config.remote.enabled {
        return None;
    }
    Enrollment::load(enrollment_dir)
        .and_then(|enrollment| config.remote.connection(enrollment.as_ref()))
        .unwrap_or_else(|error| {
            eprintln!("{error:#}; remote control disabled");
            None
        })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use futures_util::future::BoxFuture;
    use tokio::{sync::oneshot, time::timeout};

    use super::*;

    /// A fake connection that stays open until dropped, reporting when it is.
    struct Connection {
        dropped: Option<oneshot::Sender<()>>,
    }

    impl Drop for Connection {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                dropped.send(()).unwrap_or_default();
            }
        }
    }

    type Opened = tokio::sync::mpsc::UnboundedSender<(u32, oneshot::Receiver<()>)>;

    /// Each call opens a fake connection that stays up until its future is
    /// dropped.
    fn fake_connect(opened: Opened) -> impl FnMut(u32) -> BoxFuture<'static, Result<()>> {
        move |id| {
            let (dropped, on_drop) = oneshot::channel();
            opened.send((id, on_drop)).unwrap();
            let connection = Connection {
                dropped: Some(dropped),
            };
            Box::pin(async move {
                let _connection = connection;
                std::future::pending::<()>().await;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn disabled_by_default_never_connects() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let (sender, settings) = watch::channel(None::<u32>);
        let counter = Arc::clone(&attempts);
        let task = tokio::spawn(supervise_with(settings, move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<()>>()
        }));
        tokio::task::yield_now().await;
        drop(sender);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn toggling_remote_connects_and_drops_the_session() {
        let (opened, mut connections) = tokio::sync::mpsc::unbounded_channel();
        let (sender, settings) = watch::channel(None);
        let task = tokio::spawn(supervise_with(settings, fake_connect(opened)));

        // Off -> on: a session opens.
        sender.send(Some(1)).unwrap();
        let (id, dropped) = timeout(Duration::from_secs(1), connections.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(id, 1);

        // On -> off: the live session is dropped and nothing reconnects.
        sender.send(None).unwrap();
        timeout(Duration::from_secs(1), dropped)
            .await
            .unwrap()
            .unwrap();
        tokio::task::yield_now().await;
        connections.try_recv().unwrap_err();

        // Off -> on again.
        sender.send(Some(2)).unwrap();
        let (id, _dropped) = timeout(Duration::from_secs(1), connections.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(id, 2);

        task.abort();
    }
}
