# Tetra Architecture

Tetra is a modular host agent and recipe renderer for the Ultramarine Server
Dashboard. It is written in Rust and organized around a small set of cohesive
layers: the recipe engine, the command dispatcher, the dispatch queue, the
transport layer, the auth service, and the feature-gated modules.

## Crate layout

```
tetra/
├── src/
│   ├── main.rs           # CLI entry point (subcommands, argument parsing)
│   ├── lib.rs            # Public API: agent, auth, catalog, enrollment, types
│   ├── prelude.rs        # Common imports for modules (Mod, ModuleInfo, actions!, cmd!, ...)
│   ├── catalog.rs        # Recipe engine (YAML → Tera → Quadlet units)
│   ├── types.rs          # Shared module payload types (serde)
│   ├── auth/             # Login, sessions, authorization (see auth-protocol.md)
│   │   ├── service/      # AuthService: every local-socket operation (one file per area; shell_ops.rs: shell.ticket)
│   │   ├── api.rs        # Request/response/error types
│   │   ├── accounts.rs   # Login eligibility and admin groups
│   │   ├── pam.rs        # PAM password verification
│   │   ├── totp.rs, recovery.rs, passkey.rs  # Second factor and passkeys
│   │   ├── sessions.rs   # Session tokens
│   │   ├── shell.rs      # Web shell tickets
│   │   ├── users.rs      # Per-user credential records (auth/users/<uid>.json)
│   │   ├── authz.rs      # Permission table, grants, setup allowlist
│   │   ├── access.rs     # access.json, WebAuthn relying party, dashboard site
│   │   ├── dns.rs        # DNS-01 providers and credentials for access.set
│   │   ├── launcher.rs   # Launcher entries and the public page
│   │   ├── setup.rs      # First-boot setup code
│   │   ├── audit.rs      # Action log
│   │   ├── host.rs       # Host commands of the auth service (Caddy, dashboard, OOBE)
│   │   ├── seal.rs       # systemd-creds store key
│   │   ├── secrets.rs    # Sealed credentials for other services (/var/lib/tetra/secrets)
│   │   ├── store.rs      # Versioned root-only JSON files
│   │   ├── clock.rs      # Injectable wall clock
│   │   └── testing.rs    # Fakes for PAM, accounts, sealing, host (`testing` feature or tests only)
│   ├── enrollment/
│   │   ├── mod.rs        # `tetra enroll` / `tetra unenroll` (CSR, device flow)
│   │   ├── renewal.rs    # Client certificate renewal over the mTLS session
│   │   └── store.rs      # Root-only enrollment record under /var/lib/tetra/remote
│   └── agent/
│       ├── mod.rs              # Re-exports and module-level docs
│       ├── apps_account.rs     # The ultramarine-apps account user apps run under
│       ├── dispatcher.rs       # Command routing registry, RunAs
│       ├── queue.rs            # Bounded transport-to-dispatch queue
│       ├── remote.rs           # remote.enabled gate for the outbound session
│       ├── command.rs          # AgentCommand / AgentResponse types
│       ├── config.rs           # Runtime config (/etc/tetra/tetra.json)
│       ├── identity.rs         # Host keypair generation and persistence
│       ├── local_socket.rs     # Local Unix socket listener (production)
│       ├── local_protocol.rs   # Session protocol frames for local clients
│       ├── peer.rs             # SO_PEERCRED client identification
│       ├── shell.rs            # Web shell: a local connection that became a terminal
│       ├── shell/frames.rs     # Shell stream control frames
│       ├── shell/pty.rs        # PTY + systemd-run --pty, behind PtySpawner
│       ├── transport.rs        # Outbound endpoint/TLS configuration (wss:// only)
│       ├── websocket.rs        # Outbound WSS control-plane client
│       ├── dev_listener.rs     # Dev-only loopback TCP listener
│       ├── module_support.rs   # Shared module helpers
│       ├── modules.rs          # Mod trait, actions! macro, module registry
│       └── modules/            # One module per host-management surface
│           ├── settings.rs     # Always compiled; host facts and locale
│           ├── apps.rs
│           ├── files.rs
│           ├── recipes.rs
│           ├── quadlets.rs
│           ├── services.rs
│           ├── selinux.rs
│           ├── storage.rs
│           ├── network.rs      # network/{keyfile,paths,addresses,apply,certs,wifi}.rs
│           ├── samba.rs
│           ├── nfs.rs
│           ├── podman.rs
│           ├── users.rs
│           ├── reverse_proxy.rs
│           ├── power.rs
│           ├── updates.rs
│           ├── remote_access.rs
│           └── virtual_machines.rs
├── tests/                # Integration tests (see Testing)
└── systemd/, pam/, examples/
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

Rendering is deterministic apart from generated parameter values. The engine is
used by the CLI (`render` subcommand) and by the `recipes` and `apps` agent
modules. Before agent render/install writes, `catalog::verification` checks the
exact recipe/template snapshot against caller-supplied SHA-256 provenance and
enforces digest-pinned images (custom-only explicit opt-out). Tetra does not
fetch catalogs or authenticate publishers. Apps persist verified inline snapshots,
source metadata/digests, and image policy in their manifest; see
[recipes.md](recipes.md#install-time-source-verification-and-image-pinning).

## The dispatcher (`agent::dispatcher`)

The dispatcher is a registry of `Mod` implementations, keyed by module name in
a `BTreeMap` (so `agent.capabilities` lists modules in name order).
`Dispatcher::full()` registers every module compiled into the build. A command
is a JSON envelope:

```json
{
  "id": "cmd-1",
  "module": "settings",
  "action": "get_system",
  "payload": {}
}
```

Dispatcher flow:

1. Reject a command whose `signature` is an empty string. The field is not
   otherwise checked; no production transport signs commands.
2. If `module == "agent"` and `action == "capabilities"`, return the metadata for every registered module.
3. Look up the module by name (`unknown module` otherwise).
4. Ask `module.metadata(action, payload)`, which answers the shared `capabilities` and `plan` actions.
5. Take `run_as` out of the payload (or use `module.default_run_as()`) to
   pick the user host commands run as: the signed-in user, the
   `ultramarine-apps` account, root, or both user and root.
6. Call `module.handle(action, payload, user)`.

Any `Err` becomes an `AgentResponse::error` with the command's `id`.

Modules are stateless (`handle` takes `&self`). Host state lives in systemd, the
filesystem, etc., not in the module. The two modules that keep files under
Tetra's state directory (`updates`, `remote_access`) hold only their paths;
`AuthConfig::dispatcher()` registers them with the daemon's `--state-dir`.

## The dispatch queue (`agent::queue`)

Transports are async, but the dispatcher is synchronous. The local socket and
the outbound WSS session share one bounded `DispatchQueue`, whose single worker
runs `Dispatcher::dispatch` on Tokio's blocking pool, one command at a time.
A slow module never stalls the async runtime, and a panicking module fails
only its own command. The bound means a full queue returns a retryable error
instead of letting an unbounded number of transport tasks wait while a slow
host mutation is in progress.

- Default capacity: 64 commands.
- Admission is non-blocking: callers get `QueueError::Full` rather than an unbounded wait.
- A single worker serializes commands, which prevents concurrent host mutation races (systemd, files, Quadlets, storage, etc.).
- Every host command a module runs is killed (with its process group) after
  15 minutes (`module_support::COMMAND_TIMEOUT`), so a hung `systemctl`,
  `podman` or `virsh` cannot stall the queue forever.
- A caller that stops waiting does not cancel its command: it still runs, and
  the response is dropped. Use command ids to reconcile.

Future work: a typed read-only lane with bounded concurrency, without weakening
mutation ordering.

## Modules (`agent::modules`)

Each module implements the `Mod` trait (`src/agent/modules.rs`) and is gated by
a Cargo feature. The `settings` module is always compiled so the dashboard can
discover basic host facts even when other features are disabled.

```rust
pub trait Mod: Send + Sync {
    fn info(&self) -> ModuleInfo;
    fn name(&self) -> &'static str { self.info().name }
    fn metadata(&self, action: &str, payload: &Value) -> Option<Value> {
        self.info().metadata_response(action, payload)
    }
    fn default_run_as(&self) -> RunAs { RunAs::User }
    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value>;
}
```

`ModuleInfo` lists the module's actions and its `privileged_actions`, which
always run as root. Unprivileged actions run as the `user` the dispatcher
passes, through `runuser` (with `XDG_RUNTIME_DIR` set when that user's
manager runs): the session's user, or whoever the payload's `run_as` names.
A module whose host state belongs to the apps account (`podman`) overrides
`default_run_as` to `RunAs::Apps`; modules never choose users on their own.

### Adding a new module

1. Create `src/agent/modules/my_module.rs`.
2. Implement `Mod` and declare the actions with `actions!`:

```rust
use serde_json::json;

use crate::prelude::*;

#[derive(Clone, Copy, Debug)]
pub struct MyModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "my_module",
    feature: "my-module",
    description: "Does something useful",
    status: ModuleStatus::Available,
    actions: &["capabilities", "plan", "status", "do_something"],
    privileged_actions: &["do_something"],
};

impl Mod for MyModule {
    fn info(&self) -> ModuleInfo { INFO }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    // No payload: accepts any object, or `null`.
    Status => Ok(json!({ "ok": true })),
    // Inline payload struct; `payload` and `user` are in scope.
    DoSomething {
        name: String,
        #[serde(default)]
        dry_run: bool,
    } => cmd!((payload.dry_run) { &INFO, "do_something", user }
        "my-tool" ["apply", positional("name", &payload.name)?] json),
    // Or a named payload type: `Read: ReadRequest => { ... }`.
});
```

   `actions!` generates one `Deserialize` struct per action and an enum whose
   variants are the actions in snake case. `Action::from_payload` reads an
   omitted payload (`null`) as `{}`, so actions whose fields all have defaults
   accept it, and unknown actions fail with a serde error. A module whose
   handlers need state (`updates` and `remote_access` carry their paths)
   writes the enum by hand and calls `module_support::parse_action`.

3. Add the module to the `modules![...]` list in `src/agent/modules.rs`, as
   `file_name: "cargo-feature" => TypeName`. The macro declares the
   feature-gated `mod`, re-exports the type and registers it in
   `register_all`, which `Dispatcher::full()` calls:

```rust
modules![
    // ...
    my_module: "my-module" => MyModule,
];
```

4. Add the feature to `Cargo.toml`:

```toml
[features]
default = ["...", "my-module"]
my-module = []
```

5. Classify every action in `TABLE` in `src/auth/authz.rs`. Unlisted actions
   are administrator-only, and a test fails until each compiled action is
   listed.

`capabilities` and `plan` are answered by the dispatcher through
`Mod::metadata` before `handle` is called. Any signed-in user may call
them, so they must stay static: put host state (like `storage`'s ZFS
inventory) behind an action the authorization table gates.

When a payload type is shared with callers or reused across modules — like
`ServiceRequest` or the `apps` module's `AppCreateRequest`/`AppManifest` —
define it in `src/types.rs` so both the agent and external consumers can
depend on one serde schema.

### Shared helpers (`module_support`)

- `cmd!` — run a host command through `run_command_output_as`: `(dry_run)`
  previews it, `{ &INFO, action, user }` runs unprivileged actions as `user`,
  and a trailing `json` or `JSON` wraps the result (`JSON` also parses stdout
  into `data`). Commands time out after `COMMAND_TIMEOUT` (15 minutes).
- `run_command_with_input` — feed a secret on stdin instead of the command line.
- `positional` — refuse an empty payload value, or one starting with `-`,
  before it becomes a positional argument (so `podman rm -a` cannot happen).
- `option_arg` — append `--flag value` when an optional value is set.
- `safe_join` — join a relative path under a base directory, rejecting absolute paths and `..`.
- `resolve_under` / `write_under` / `remove_under` — `safe_join` that also
  refuses symlinks below the base; `write_under` writes atomically with a
  given mode and creates parent directories.
- `apply_selinux` — run `semanage fcontext` + `restorecon` when a payload includes `selinux` options.
- `apps_account::{write_owned, create_dir_owned}` — `write_under` and
  directory creation that hand the result to the `ultramarine-apps` account
  (`Owner`, `lchown`, refusing symlinks below its home), for apps-scope
  Quadlets and bundles.
- `restorecon` — reset a path to the policy's default label (skipped without SELinux).
- `parse_action` — decode `{action: payload}` into an action enum.
- `Commands` — record a sequence of commands for one action, including failures that are tolerated.

## Transports

The production transports feed the same command envelope into the same
`DispatchQueue`.

### Local Unix socket (`agent-serve`)

Production transport for local clients (the dashboard container and the server
OOBE), and the only listener `tetra.service` runs. The socket at
`/run/tetra/tetra.sock` is created by `tetra.socket` as `root:tetra 0660` and
passed in through systemd socket activation; outside systemd Tetra binds it
itself. Each connection is identified by its peer credentials (dashboard or
OOBE) and speaks the session protocol: every request carries a Tetra-issued
token, and `auth::AuthService` authenticates and authorizes it. See
[auth-protocol.md](auth-protocol.md).

- `local_socket.rs` — socket activation, fallback bind, accept loop.
- `peer.rs` — maps the peer UID to the dashboard or the OOBE.
- `local_protocol.rs` — `hello`, `request` and `response` frames.
- `shell.rs`, `shell/` — web shells. A connection whose first request is
  `shell.open` (with a ticket from `shell.ticket`) becomes a terminal: Tetra
  opens a PTY, runs the user's login shell as that user through
  `systemd-run --pty` (`PAMName=tetra-shell`), and pipes binary messages to
  and from the PTY, with JSON `resize` and `exit` control frames. The
  dashboard only relays bytes; no other listener is involved. Shells end with
  their session, after 30 minutes without input, or when the connection
  closes, and are limited to 4 per user and 16 per host. See
  [auth-protocol.md](auth-protocol.md#web-shell).

### Outbound WSS (remote control)

Tetra dials out to a control plane over WSS using mTLS. This avoids
firewall/NAT issues because the connection is outbound. `control_plane_url`
must be `wss://`, and the client certificate, client key and server CA are all
required (`TransportConfig::wss_url`). The session is gated by
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
- `transport.rs` — `control_plane_url` and the client cert/key/CA paths.
- `enrollment/renewal.rs` — renews the client certificate over the session.

### Development transport (`dev-listener` feature)

`dev_listener.rs` is only compiled with the `dev-listener` Cargo feature.
Release builds leave it off, so production binaries cannot listen on the
network.

**Loopback WebSocket (`agent-ws-serve`).** Runs the daemon and serves the same
`LocalServer` session protocol and `AuthService` as the Unix socket, over TCP
for dashboard or OOBE development. Every request still needs a Tetra-issued
session token and goes through the normal authorization and action log. TCP
has no peer credentials, so `--client dashboard|oobe` (default `dashboard`)
is applied to every connection. Any process on the host can connect and claim
that configured client; use it only for development. `--listen` refuses every
non-loopback address. TLS is intentionally omitted: this listener is for
loopback-only development; plain TLS would not identify the local process,
while mutual TLS would require a separate client-credential setup. It does not
make the dev listener suitable for remote access. Production uses
`SO_PEERCRED` on the Unix socket.

### Local dispatch (`agent-dispatch`)

One-shot CLI that reads a JSON command envelope from a file (or stdin) and
routes it through `Dispatcher::full()`. No authorization; useful for debugging
and integration testing.

## Authentication and authorization

### Local clients

Users log in through Tetra (PAM password plus TOTP, or a passkey) and get a
session token; the local socket identifies the client from its peer
credentials. Every module action is authorized from the user's admin status
and grants (`auth::authz`). Unprivileged actions run as the session user via
`runuser` (or as `ultramarine-apps`, with `run_as: apps` or the module's
default); privileged ones as root. A web shell always runs as the session's
user, in its own transient unit; elevation is `sudo` inside it. See
[auth-protocol.md](auth-protocol.md).

## User apps and the apps account

User apps are rootless Quadlets of one system account, `ultramarine-apps`
(UID/GID 242, home `/var/lib/ultramarine-apps`, from
`systemd/tetra.sysusers.conf` and `systemd/tetra.tmpfiles.conf`), whoever
installs them. `apps` and `quadlets` default to this `apps` scope
(`types::AppScope`); `system` scope keeps rootful Quadlets for real system
services. There is no per-user scope.

- Files: units in `~/.config/containers/systemd`, bundles in
  `~/.local/share/tetra/quadlets/<app>`. Tetra writes them as root,
  atomically, then `lchown`s each file and directory to the account
  (`apps_account::Owner`), after checking that nothing from the home down is
  a symlink.
- Host setup (`AppsAccount::provision`, on `apps.create`/`update` with
  `converge`): subordinate UID/GID ranges (`usermod --add-subuids/
  --add-subgids`, since `systemd-sysusers` allocates none), lingering, the
  user manager started, and the rootful storage labels for its
  `~/.local/share/containers/storage` (`semanage fcontext -a -e`).
- systemd: `systemctl --user -M ultramarine-apps@` (`ServiceScope::Apps`).
- Reads: `podman` defaults to `run_as: apps`; `agent-serve` warns at startup
  when the account is missing or its IDs are not 242.

### Remote and development transports

- Outbound WSS uses mTLS (client certificate + server CA verification). Its
  commands are authorized as the remote controller, which may run every
  action, and logged as remote actions. The `user` field of a remote command
  is cleared, so every remote action runs as root.
- The development TCP listener uses the same token-based session protocol as
  the Unix socket, including PAM/TOTP or passkeys, per-request authorization,
  and session-bound user execution. It is loopback-only and is not a production
  transport.

## Data paths

Default mutable paths (bootc-friendly):

| Path                       | Purpose                                     |
| -------------------------- | ------------------------------------------- |
| `/var/lib/tetra/identity/` | Host Ed25519 keypair, used for the host fingerprint in `hello`. |
| `/var/lib/tetra/auth/`     | Login state: sealed store key, per-user credentials, grants, sessions, setup code (root-only). |
| `/var/lib/tetra/access.json`, `launcher.json`, `updates.json`, `setup-complete`, `audit/` | Access mode, launcher, update policy, setup marker, action log. |
| `/var/lib/tetra/secrets/`  | Credentials for other services, sealed with `systemd-creds`. |
| `/var/lib/tetra/remote/`   | Remote-control client key, certificate, server CA and controller record (root-only). |
| `/var/lib/tetra/quadlets/` | Companion files and `app.json` manifests of system-scope apps. |
| `/var/lib/ultramarine-apps/` | Home of the apps account: apps-scope Quadlets (`.config/containers/systemd`), bundles (`.local/share/tetra/quadlets`) and rootless Podman storage, owned by the account. |
| `/run/tetra/`              | The socket, the setup code for the console, short-lived files. |

Generated identities, enrollment state, and rotation metadata must live in
mutable paths. Installed policy/unit files may live in immutable deployment
content.

## Threading and concurrency model

```text
[Transport tasks]       [Queue]              [Blocking pool]      [Modules]
      |                    |                     |                     |
      |-- accept conn -->  |                     |                     |
      |-- parse frame -->  |                     |                     |
      |-- admit cmd ---->  |-- DispatchQueue --> |-- spawn_blocking -> |-- Dispatcher
      |                    |  (bounded, 64)      |  (one at a time)    |  (BTreeMap registry)
      |                    |                     |                     |
```

- Tokio accepts connections concurrently, and the local socket handles
  requests concurrently (login, sessions and other non-module operations do
  not wait for the queue).
- Web shells never touch the queue: each runs on its own connection task,
  with one task per direction pumping bytes and a supervisor that checks the
  session every 5 seconds.
- A single queue worker serializes module commands and runs each one on the
  blocking pool, so long-running module actions never block the async
  transports.

## Testing

- Unit tests live next to the code they test (`#[cfg(test)]` modules).
  The web shell's stream runs over a real socket against a fake
  `PtySpawner` (`agent::shell::pty::FakeSpawner`); the real systemd shell
  test is `#[ignore]`d (it needs root:
  `sudo TETRA_TEST_SHELL_USER=alice cargo test -- --ignored real_systemd`).
- Integration tests in `tests/` use the fakes in `tetra::auth::testing` (the
  `testing` feature, enabled for them through `dev-dependencies`), with shared
  helpers in `tests/common/mod.rs`:
  - `agent_dispatcher.rs` — dispatcher and queue routing, `capabilities`/`plan`, module actions (mostly dry runs and temp directories).
  - `auth_login.rs` — password, TOTP, recovery codes and sessions.
  - `auth_passkeys.rs` — passkey registration and login, passkey availability.
  - `auth_authorization.rs` — admins, default permissions, grants, the action log.
  - `auth_launcher.rs` — launcher visibility, `launcher.can_access`, the public page.
  - `auth_setup.rs` — the setup code, setup session and completion.
  - `auth_oobe.rs` — the OOBE flow: setup allowlist, `access.set`, throttle, handoff.
  - `auth_shell.rs` — web shell tickets: single use, expiry, binding to the session and account, the session checks of a running shell.
  - `remote_enrollment.rs` — `tetra enroll`/`unenroll`, the mTLS session and certificate renewal, against an in-process controller (runs the real binary).
- The `agent-dispatch` CLI is the easiest way to exercise a module manually:

```sh
cargo run -- agent-dispatch examples/settings.command.json
```

Use `cargo test --all-features` to run the full suite.
