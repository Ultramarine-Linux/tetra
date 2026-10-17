# Tetra

Tetra is a modular host agent and recipe renderer for the [Ultramarine Server Dashboard](https://github.com/Ultramarine-Linux/dashboard).
It is organized around a single dispatcher with independent,
feature-gated modules for apps, files, recipes, SELinux, services, Quadlets,
reverse-proxy, Podman, Samba, NFS, users, and virtual machines. The `settings`
module is always compiled so the control plane can discover basic host facts.

Local clients (the dashboard container and the server OOBE) talk to Tetra over
a Unix socket at `/run/tetra/tetra.sock` (`agent-serve`). This is the only
listener a production install runs; Tetra does not listen on the network.
The socket carries the authenticated WebSocket protocol, with Ed25519-signed
command frames.

An outbound mTLS WSS connection to a remote control plane (`agent-connect`)
also exists. When the agent runs inside a VM, the same JSON frame protocol can
be carried over a virtio-vsock stream.

For development, `agent-ws-serve` runs the same authenticated WebSocket
protocol on a TCP listener.

The local `agent-dispatch` command accepts the same command envelope shape for
one-shot debugging. See [docs/agent-protocol.md](docs/agent-protocol.md) for
the controller-facing API, connection negotiation, and agent protocol reference.

Recipes are declared in YAML, and Quadlet generation uses Tera templates. A
recipe declares metadata, UI parameters, requirements, and a list of resources
to render.

## Documentation

- [Agent protocol reference](docs/agent-protocol.md) — Connection negotiation, authentication, and the full module action catalog.
- [Recipe authoring guide](docs/recipes.md) — How to write recipes, parameters, templates, and resources.
- [Architecture overview](docs/architecture.md) — Crate layout, dispatcher, queue, transports, and how to add a module.
- [Troubleshooting](docs/troubleshooting.md) — Common issues with TLS, identity, WebSocket auth, recipe rendering, SELinux, and queue backpressure.

## Feature Flags

Default build features:

- `apps`
- `files`
- `recipes`
- `selinux`
- `services`
- `quadlets`
- `reverse-proxy`
- `podman`
- `samba`
- `nfs`
- `users`
- `storage`
- `network`

Additional optional features:

- `virtual-machines`

Build with every module:

```sh
cargo build --all-features
```

Build with only recipe rendering and Quadlet management:

```sh
cargo build --no-default-features --features recipes,quadlets
```

## Render Recipes

Render a recipe into container unit files and companion files:

```sh
cargo run -- render schema.yaml --templates-dir ./templates --output-dir ./quadlets
```

Preview without writing:

```sh
cargo run -- render schema.yaml --templates-dir ./templates --dry-run
```

Parameter values are supplied as a simple YAML map:

```yaml
domain: cloud.example.com
enable_redis: true
```

Pass them with:

```sh
cargo run -- render schema.yaml --values values.yaml --templates-dir ./templates --output-dir ./quadlets
```

## Agent Commands

### Local dispatch

The one-shot CLI accepts the same JSON command envelope used by transports:

```json
{
  "id": "cmd-1",
  "module": "settings",
  "action": "get_system",
  "payload": {}
}
```

Run it:

```sh
cargo run -- agent-dispatch examples/settings.command.json
```

`examples/apps.command.json` shows a dry-run `apps.create` that cooks an
inline recipe into an installed app bundle.

### Local socket (production)

`agent-serve` is the host agent daemon. It serves the authenticated WebSocket
protocol to local clients over a Unix socket. Under systemd the socket comes
from `tetra.socket` through socket activation; otherwise Tetra binds
`--socket` (default `/run/tetra/tetra.sock`) with mode `0660`:

```sh
cargo run -- agent-serve \
  --socket /tmp/tetra.sock \
  --identity-dir /tmp/tetra-identity \
  --controller-public-key "$TETRA_CONTROLLER_PUBLIC_KEY"
```

Clients open a WebSocket over the Unix stream; the HTTP `Host` and path are
ignored. With Node's `ws`, use `ws+unix:///run/tetra/tetra.sock`.

### Inbound WebSocket server (development)

`agent-ws-serve` runs an authenticated WebSocket for dashboard clients. It
requires an enrolled controller Ed25519 public key before accepting commands.
The host identity is automatically generated under `/var/lib/tetra/identity`:

```sh
cargo run -- agent-ws-serve \
  --listen 127.0.0.1:7780 \
  --controller-public-key "$TETRA_CONTROLLER_PUBLIC_KEY"
```

For non-loopback addresses, TLS is required:

```sh
cargo run -- agent-ws-serve \
  --listen 0.0.0.0:7780 \
  --tls-cert /etc/tetra/tetra.crt \
  --tls-key /etc/tetra/tetra.key
```

### Outbound WSS control plane (production)

`agent-connect` dials out to the dashboard/control plane and maintains a
persistent connection:

```sh
cargo run -- agent-connect --config examples/transport.json --host-id myhost
```

The transport config JSON contains:

```json
{
  "control_plane_url": "wss://dashboard.example.com/tetra/agent",
  "client_cert_path": "/var/lib/tetra/identity/agent.crt",
  "client_key_path": "/var/lib/tetra/identity/agent.key",
  "server_ca_path": "/var/lib/tetra/identity/dashboard-ca.crt"
}
```

### Vsock smoke test

For a VM guest with virtio-vsock enabled, run Tetra as a small test listener
inside the guest:

```sh
cargo run --all-features -- agent-vsock-serve --port 2048
```

From the VM host, connect to the guest CID and send one command JSON object.
For libvirt guests, find the CID with `virsh dumpxml VM_NAME | grep -A4 -i vsock`.

```sh
printf '%s' '{"id":"cmd-1","module":"settings","action":"get_system","payload":{}}' \
  | socat - VSOCK-CONNECT:GUEST_CID:2048
```

The listener reads one command per connection and writes one `AgentResponse`
JSON object. This is a development smoke test for host-to-guest command
dispatch over vsock.

## Systemd

`systemd/tetra.socket` creates `/run/tetra/tetra.sock` as `root:tetra`, mode
`0660`, and socket-activates `systemd/tetra.service`, which runs
`agent-serve` and persists identity under `/var/lib/tetra/identity`. The
service does not bind a TCP port.

`systemd/tetra.sysusers.conf` creates the `tetra` group. To let the dashboard
container reach Tetra, bind-mount the socket into the container and run it
with the `tetra` group (for a Quadlet, `Volume=/run/tetra/tetra.sock:/run/tetra/tetra.sock`
and `GroupAdd=tetra`, or `GroupAdd=keep-groups` for a rootless container whose
user is in `tetra`).

## Host enrollment

The host-side `enroll` command uses a device authorization flow. It generates
the host identity and TLS material, prints a Dashboard verification URL and
short approval code, then waits for an authenticated Dashboard user to approve
the request:

```text
tetra enroll --dashboard-url https://dashboard.example.com \\
  --agent-url wss://host.example.com:9443 \\
  --listen 0.0.0.0:9443 \\
  --display-name host-01
```

The Dashboard stores the controller private key; Tetra stores only the
controller public key. Use `--agent-url` for the address Dashboard should use
to reach the host and `--listen` for the local bind address and port. The host's
firewall or private network must allow the Dashboard to reach the configured
WebSocket URL. If omitted, `--listen` defaults to `0.0.0.0:7780`.

`tetra.service` no longer runs a TCP listener, so the `--listen` and
`--agent-url` values recorded by `enroll` are not served by the default
install. Run `agent-ws-serve` yourself if a Dashboard must reach this host
over the network.

## Authentication and Elevation

Tetra uses Ed25519 asymmetric key authentication for inbound WebSocket
sessions. The dashboard stores the private key server-side; Tetra stores only
the controller public key. Outbound WSS uses mTLS for transport identity.

Mutating host actions execute by default. Privileged actions require an
in-memory, session-bound elevation grant obtained by verifying the
administrator password against the host shadow database. The grant expires
after a configurable TTL (default 30 minutes).

To discover enabled modules and actions, send:

```json
{
  "id": "cmd-capabilities",
  "module": "agent",
  "action": "capabilities",
  "payload": {}
}
```

Each module also supports its own `capabilities` action.

## SELinux

Fedora and SELinux-oriented installs can use the `selinux` module to inspect
SELinux status, list and set booleans, manage file-context rules with
`semanage fcontext`, and run `restorecon` after managed file changes.

Modules that create or manage paths also accept a shared `selinux` payload to
apply file-context rules and relabel paths as part of the same action. For
example, a Samba share path can be labeled while updating generated config:

```json
{
  "id": "cmd-samba-config",
  "module": "samba",
  "action": "set_config",
  "payload": {
    "contents": "[media]\npath = /srv/media\n",
    "dry_run": true,
    "selinux": {
      "path": "/srv/media",
      "context_type": "samba_share_t",
      "recursive": true
    }
  }
}
```
