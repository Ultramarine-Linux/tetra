use std::sync::Arc;

#[cfg(target_os = "linux")]
use std::{
    io::{Read, Write},
    thread,
};

#[cfg(any(test, target_os = "linux"))]
use anyhow::Context;
use anyhow::{Result, bail};

#[cfg(any(test, target_os = "linux"))]
use super::AgentCommand;
use super::Dispatcher;

/// Configuration for the vsock agent smoke-test server (`agent-vsock-serve`).
///
/// This is the host→guest test path: run Tetra inside a VM guest and have the
/// host send a single command JSON object per connection. The production
/// control-plane transport is the WSS connection in [`super::websocket`].
#[derive(Debug, Clone, clap::Parser)]
pub struct VsockAgentConfig {
    /// Vsock port to listen on inside the VM guest.
    #[arg(long, default_value_t = 2048)]
    pub port: u32,

    /// Maximum accepted command JSON body size in bytes.
    #[arg(long, default_value_t = 1024 * 1024)]
    pub max_command_bytes: usize,
}
impl VsockAgentConfig {
    /// Listen on a vsock port and handle one command per connection.
    ///
    /// Concurrency here is OS threads (not tokio tasks) because vsock I/O on
    /// Linux is a blocking `Read`/`Write` surface — there's no async vsock crate in
    /// the dependency set. Each connection runs on its own thread and dispatches
    /// through the shared [`Dispatcher`].
    pub fn serve(self) -> Result<()> {
        self.serve_with_dispatcher(&Arc::new(Dispatcher::full()))
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unused_self)]
    fn serve_with_dispatcher(&self, _dispatcher: &Arc<Dispatcher>) -> Result<()> {
        bail!("agent-vsock-serve is only supported on Linux")
    }

    #[cfg(target_os = "linux")]
    fn serve_with_dispatcher(&self, dispatcher: &Arc<Dispatcher>) -> Result<()> {
        use socket2::{Domain, SockAddr, Socket, Type};

        // VMADDR_CID_ANY (-1 / u32::MAX) tells the host kernel to accept
        // connections from any guest CID, which is what a smoke-test listener
        // wants — we don't know ahead of time which guest will connect.
        const VMADDR_CID_ANY: u32 = u32::MAX;

        let listener = Socket::new(Domain::VSOCK, Type::STREAM, None)
            .context("failed to create AF_VSOCK listener")?;
        listener
            .bind(&SockAddr::vsock(VMADDR_CID_ANY, self.port))
            .with_context(|| format!("failed to bind vsock listener on port {}", self.port))?;
        listener
            .listen(128)
            .with_context(|| format!("failed to listen on vsock port {}", self.port))?;

        eprintln!("serving Tetra agent vsock API on port {}", self.port);

        loop {
            let (stream, peer) = listener
                .accept()
                .context("failed to accept vsock connection")?;
            let dispatcher = Arc::clone(dispatcher);
            let max_command_bytes = self.max_command_bytes;
            let peer = peer.as_vsock_address().map_or_else(
                || "cid=- port=-".into(),
                |(cid, port)| format!("cid={cid} port={port}"),
            );

            thread::spawn(move || {
                if let Err(error) = handle_connection(stream, &dispatcher, max_command_bytes) {
                    eprintln!("source={peer} status=500 error={error:?}");
                } else {
                    eprintln!("source={peer} status=200");
                }
            });
        }
    }
}

impl Default for VsockAgentConfig {
    fn default() -> Self {
        Self {
            port: 2048,
            max_command_bytes: 1024 * 1024,
        }
    }
}

#[cfg(target_os = "linux")]
fn handle_connection(
    mut stream: socket2::Socket,
    dispatcher: &Arc<Dispatcher>,
    max_command_bytes: usize,
) -> Result<()> {
    let mut command_text = String::new();
    // `take(max + 1)` lets us detect oversized payloads: if the peer sends
    // exactly `max` bytes we accept it; if it sends more, the extra byte gets
    // read into `command_text` and `dispatch_command_text` rejects it below.
    Read::by_ref(&mut stream)
        .take((max_command_bytes as u64).saturating_add(1))
        .read_to_string(&mut command_text)
        .context("failed to read vsock command JSON")?;

    let response_text = dispatch_command_text(dispatcher, &command_text, max_command_bytes)?;
    stream
        .write_all(response_text.as_bytes())
        .context("failed to write vsock response JSON")?;
    stream
        .write_all(b"\n")
        .context("failed to terminate vsock response JSON")?;
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn dispatch_command_text(
    dispatcher: &Dispatcher,
    command_text: &str,
    max_command_bytes: usize,
) -> Result<String> {
    if command_text.len() > max_command_bytes {
        bail!("command body exceeds {max_command_bytes} bytes");
    }

    let command: AgentCommand =
        serde_json::from_str(command_text).context("failed to parse agent command JSON")?;
    let response = dispatcher.dispatch(command);
    serde_json::to_string_pretty(&response).context("failed to serialize agent response")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn dispatches_one_command_text_frame() {
        let dispatcher = Dispatcher::full();
        let response_text = dispatch_command_text(
            &dispatcher,
            r#"{"id":"cmd-1","module":"settings","action":"get_system","payload":null}"#,
            1024,
        )
        .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_text).unwrap();

        println!("{response}");

        assert_eq!(response["id"], "cmd-1");
        assert_eq!(response["ok"], true);
        assert!(response["payload"]["os"].is_string());
    }

    #[test]
    fn rejects_oversized_command_text() {
        let dispatcher = Dispatcher::full();
        let error = dispatch_command_text(&dispatcher, &json!({ "id": "x" }).to_string(), 1)
            .unwrap_err()
            .to_string();

        assert!(error.contains("command body exceeds 1 bytes"));
    }
}
