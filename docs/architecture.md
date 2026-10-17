# Tetra Architecture

Tetra is a modular host agent and recipe renderer for the Ultramarine Server
Dashboard. It is written in Rust and organized around a small set of cohesive
layers: the recipe engine, the command dispatcher, the actor backend, the
transport layer, and the feature-gated modules.

## Crate layout

```
tetra/
├── src/
│   ├── main.rs          # CLI entry point (subcommands, argument parsing)
│   ├── lib.rs           # Public API: agent + catalog + prelude
│   ├── catalog.rs       # Recipe engine (YAML → Tera → Quadlet units)
│   ├── types.rs          # Shared module payload types (serde)
│   ├── enrollment/
│   │   ├── mod.rs        # `tetra enroll` / `tetra unenroll` (CSR, device flow)
│   │   └── store.rs      # Root-only enrollment record under /var/lib/tetra/remote
│   └── agent/
│       ├── mod.rs              # Re-exports and module-level docs
│       ├── dispatcher.rs       # Command routing registry
│       ├── backend.rs          # Kameo actor wrapping the dispatcher
│       ├── queue.rs            # Bounded transport-to-dispatch queue
│       ├── remote.rs           # remote.enabled gate for the outbound session
│       ├── command.rs          # AgentCommand / AgentResponse types
│       ├── config.rs           # Runtime config (/etc/tetra/tetra.json)
│       ├── messages.rs         # Internal actor message types
│       ├── protocol.rs         # JSON frame protocol for transports
│       ├── crypto.rs           # Ed25519 signing/verification
│       ├── identity.rs         # Host keypair generation and persistence
│       ├── local_socket.rs     # Local Unix socket listener (production)
│       ├── verify_password.rs  # Shadow password verification
│       ├── transport.rs        # Shared endpoint/TLS configuration
│       ├── websocket.rs        # Outbound WSS control-plane client
│       ├── websocket_server.rs # Authenticated WebSocket protocol (ServerState)
│       ├── dev_listener.rs     # Dev-only TCP listener (`dev-listener` feature)
│       ├── vsock.rs            # Virtio-vsock smoke-test transport
│       ├── module_support.rs   # Shared module helpers
│       └── modules/            # One module per host-management surface
│           ├── mod.rs          # Default dispatcher builder
│           ├── settings.rs     # Always compiled; host facts
│           ├── apps.rs
│           ├── files.rs
│           ├── recipes.rs
│           ├── quadlets.rs
│           ├── services.rs
│           ├── selinux.rs
│           ├── storage.rs
│           ├── network.rs
│           ├── samba.rs
│           ├── nfs.rs
│           ├── podman.rs
│           ├── users.rs
│           ├── reverse_proxy.rs
│           └── virtual_machines.rs
```

## The recipe engine (`catalog`)

The recipe engine (`src/catalog.rs`) turns YAML recipes into rendered Quadlet
unit files and companion files using [Tera](https://keats.github.io/tera/docs/)
templates.

Key concepts:

- `AppRecipe` — parsed and validated YAML recipe.
- `Parameter` — user-facing inputs with types, defaults, validation, and optional generation (e.g. `random_32` secrets).
- `Resource` — a file to render (container, network, volume, pod, kube, or plain file).
- `RenderedResource` — the final filename + contents produced by two-pass Tera rendering.

Rendering is stateless and deterministic. The engine is used both by the CLI
(`render` subcommand) and by the `recipes` agent module.

## The dispatcher (`agent::dispatcher`)

The dispatcher is a registry of `AgentModule` implementations. A command is a
JSON envelope:

```json
{
  "id": "cmd-1",
  "module": "settings",
  "action": "get_system",
  "payload": {}
}
```

Dispatcher flow:

1. Verify the command signature placeholder (future: full Ed25519 verification).
2. If `module == "agent"` and `action == "capabilities"`, return the metadata for every registered module.
3. Look up the module by name.
4. Call `module.handle(action, payload, user)`, converting any `Err` into an `AgentResponse::error`.

Modules are stateless (`handle` takes `&self`). Host state lives in systemd, the
filesystem, etc., not in the module.

## The actor backend (`agent::backend`)

Transports are async, but the dispatcher is synchronous. To let multiple
transports share the same dispatcher without `&mut` contention, the dispatcher
is wrapped in a Kameo actor (`AgentBackend`).

- `AgentBackend::spawn_default()` builds the default feature-gated dispatcher and returns an `ActorRef`.
- Each transport task `ask`s the actor with a `DispatchCommand`.
- Kameo serializes messages on the actor's task, so the dispatcher's `&self`-only API stays sound.

## The dispatch queue (`agent::queue`)

Before a command reaches the actor, it passes through a bounded
`DispatchQueue`. This prevents an unbounded number of transport tasks from
waiting when a slow host mutation is in progress.

- Default capacity: 64 commands.
- Admission is non-blocking: callers get `QueueError::Full` rather than an unbounded wait.
- A single worker serializes currently dispatched commands.
- This conservative policy prevents concurrent host mutation races (systemd, files, Quadlets, storage, etc.).

Future work: a typed read-only lane with bounded concurrency, without weakening
mutation ordering.

## Modules (`agent::modules`)

Each module implements `AgentModule` and is gated by a Cargo feature. The
`settings` module is always compiled so the dashboard can discover basic host
facts even when other features are disabled.

### Adding a new module

1. Create `src/agent/modules/my_module.rs`.
2. Implement `AgentModule`:

```rust
use crate::agent::{AgentModule, module_support::{ModuleInfo, ModuleStatus, handle_metadata, unsupported_action}};
use anyhow::Result;
use serde_json::{Value, json};

pub struct MyModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "my_module",
    feature: "my-module",
    description: "Does something useful",
    status: ModuleStatus::Available,
    actions: &["capabilities", "do_something"],
    privileged_actions: &[],
};

impl AgentModule for MyModule {
    fn info(&self) -> ModuleInfo { INFO }

    fn handle(&self, action: &str, payload: Value, _user: Option<&str>) -> Result<Value> {
        if let Some(response) = handle_metadata(INFO, action, &payload) {
            return Ok(response);
        }
        match action {
            "do_something" => {
                // Parse payload, do work, return JSON
                Ok(json!({ "ok": true }))
            }
            _ => unsupported_action(INFO.name, action),
        }
    }
}
```

3. Add the feature gate in `src/agent/modules/mod.rs`:

```rust
#[cfg(feature = "my-module")]
pub mod my_module;
```

4. Register it in `default_dispatcher()`:

```rust
#[cfg(feature = "my-module")]
let dispatcher = dispatcher.with_module(my_module::MyModule);
```

5. Add the feature to `Cargo.toml`:

```toml
[features]
default = ["...", "my-module"]
my-module = []
```

When a payload type is shared with callers or reused across modules — like
`ServiceRequest` or the `apps` module's `AppCreateRequest`/`AppManifest` —
define it in `src/types.rs` so both the agent and external consumers can
depend on one serde schema.

### Shared helpers (`module_support`)

- `handle_metadata` — automatically serves the shared `capabilities` and `plan` actions for every module.
- `run_command_output_as` — run a shell command, optionally as `TETRA_UNPRIVILEGED_USER`, with stdout/stderr capture.
- `apply_selinux` — run `semanage fcontext` + `restorecon` when a payload includes `selinux` options.
- `safe_join` — resolve a path under a base directory while rejecting traversal escapes.

## Transports

Tetra exposes the same command envelope over multiple transports. All transports
feed into the same `DispatchQueue`.

### Local Unix socket (`agent-serve`)

Production transport for local clients (the dashboard container and the server
OOBE), and the only listener `tetra.service` runs. The socket at
`/run/tetra/tetra.sock` is created by `tetra.socket` as `root:tetra 0660` and
passed in through systemd socket activation; outside systemd Tetra binds it
itself. It carries the same authenticated WebSocket protocol as
`agent-ws-serve`.

- `local_socket.rs` — socket activation, fallback bind, accept loop.
- `websocket_server.rs` — `ServerState`, the per-connection protocol shared with the TCP listener.

### Outbound WSS (remote control)

Tetra dials out to a control plane over WSS using mTLS. This avoids
firewall/NAT issues because the connection is outbound. It is gated by
`remote.enabled` in `/etc/tetra/tetra.json` (default `false`). `agent-serve`
re-reads the file on `SIGHUP`, starts the session when the gate opens and drops
it when the gate closes. `agent-connect` runs the session standalone under the
same gate. The client certificate, server CA, host id and URL come from the
enrollment written by `tetra enroll` (see
[remote-enrollment.md](remote-enrollment.md)) unless `remote.*` overrides them.
Disabling the gate keeps the enrollment; `tetra unenroll` removes it.

Key files:

- `config.rs` — runtime config (`remote.*`), fails closed on invalid files.
- `remote.rs` — supervisor that runs or drops the session as the setting changes, and the `SIGHUP` reload.
- `websocket.rs` — outbound WSS client with reconnection.
- `transport.rs` — shared config parsing (`control_plane_url`, client cert/key paths, CA path).

### Inbound WebSocket (`agent-ws-serve`)

Development transport, compiled only with the `dev-listener` Cargo feature.
Release builds leave it off, so production binaries cannot listen on the
network. An authenticated WebSocket listener that accepts
Ed25519-signed command frames from a controller client. Requires an explicitly
configured controller public key before accepting commands.

- Loopback `ws://` is allowed without TLS.
- Non-loopback addresses require `--tls-cert` and `--tls-key`.
- `dev_listener.rs` — TCP bind, optional TLS, loopback-or-TLS check.
- `websocket_server.rs` — challenge/auth handshake and session management, shared with the local socket.

### Vsock (`agent-vsock-serve`)

VM guest smoke-test transport over virtio-vsock. One command per connection.
Not intended for production; future work is to route it through the shared
`DispatchQueue`.

### Local dispatch (`agent-dispatch`)

One-shot CLI that accepts a JSON command envelope file and routes it through the
same dispatcher. Useful for debugging and integration testing.

## Authentication and elevation

### Transport identity

- Outbound WSS uses mTLS (client certificate + server CA verification).
- Inbound WebSocket uses Ed25519 challenge-response: Tetra generates a host
  identity keypair on first start and stores it under `/var/lib/tetra/identity`.
  The dashboard stores the controller private key server-side.

### Command authorization

- Authenticated commands include session id, sequence, timestamp, nonce,
  command id, module, action, payload, and signature.
- Default timestamp skew allowance: five minutes.
- Nonces are replay-protected with bounded per-session state.

### Privilege elevation

Tetra can run as root. Unprivileged actions optionally run as
`TETRA_UNPRIVILEGED_USER` via `runuser`. Privileged actions require an
in-memory, session-bound elevation grant obtained by verifying the administrator
password against the host shadow database (`unix_chkpwd`). The grant expires
after a configurable TTL (default 30 minutes).

## Data paths

Default mutable paths (bootc-friendly):

| Path                       | Purpose                                     |
| -------------------------- | ------------------------------------------- |
| `/var/lib/tetra/identity/` | Host Ed25519 keypair and controller key.    |
| `/var/lib/tetra/remote/`   | Remote-control client key, certificate, server CA and controller record (root-only). |
| `/run/tetra/`              | Runtime/session data.                       |
| `/var/lib/tetra/config/`   | Optional configuration overrides.           |

Generated identities, enrollment state, and rotation metadata must live in
mutable paths. Installed policy/unit files may live in immutable deployment
content.

## Threading and concurrency model

```text
[Transport tasks]       [Queue]              [Actor]              [Modules]
      |                    |                     |                     |
      |-- accept conn -->  |                     |                     |
      |-- parse frame -->  |                     |                     |
      |-- admit cmd ---->  |-- DispatchQueue --> |-- AgentBackend -->  |-- Dispatcher
      |                    |  (bounded, 64)      |  (Kameo actor)      |  (BTreeMap registry)
      |                    |                     |                     |
```

- Tokio accepts connections concurrently.
- A single queue worker serializes commands before they reach the actor.
- Kameo serializes actor message handling, but long-running module actions do
  not block other transports because each `ask` is awaited independently by its
  caller.

## Testing

- Unit tests live next to the code they test (`#[cfg(test)]` modules).
- Integration tests are in `tests/agent_dispatcher.rs`.
- The `agent-dispatch` CLI is the easiest way to exercise a module manually:

```sh
cargo run -- agent-dispatch examples/settings.command.json
```

Use `cargo test --all-features` to run the full suite.
