# Troubleshooting

This guide covers common issues when running, developing, and deploying Tetra.

## Build issues

### `cargo build` fails with missing OpenSSL / rustls errors

Tetra uses `tokio-tungstenite` with `rustls-tls-native-roots`. Ensure you have
system CA certificates available and Rust is up to date (edition 2024 is
required).

```sh
# On Fedora / Ultramarine. pam-devel and clang-devel are needed to generate
# the libpam bindings; openssl-devel for webauthn-rs.
sudo dnf install openssl-devel pam-devel clang-devel ca-certificates

# Update Rust if edition 2024 is not recognized
rustup update
```

### Module not found when building with `--no-default-features`

The `settings` module is always compiled, but everything else is feature-gated.
If you disable defaults, include the features you need explicitly:

```sh
cargo build --no-default-features --features recipes,quadlets
```

See `Cargo.toml` for the full feature list.

## Identity and TLS

### `agent-connect` fails with TLS certificate verification errors

Check that the transport config points to valid PEM files and that the server CA
is trusted:

```json
{
  "control_plane_url": "wss://dashboard.example.com/tetra/agent",
  "client_cert_path": "/var/lib/tetra/remote/client.crt",
  "client_key_path": "/var/lib/tetra/remote/client.key",
  "server_ca_path": "/var/lib/tetra/remote/server-ca.crt"
}
```

Common causes:
- `control_plane_url` is not `wss://`. Tetra refuses `ws://` and any other
  scheme, and also refuses a config without all three TLS paths.
- Files are missing or have incorrect permissions.
- The `server_ca_path` does not match the CA that signed the server certificate.
- The hostname in `control_plane_url` does not match the certificate SAN.

### Leftover files in `/etc/tetra` from the old `tetra enroll`

Hosts enrolled before outbound enrollment may still have these files from the
old inbound flow:

- `/etc/tetra/enrollment.json`
- `/etc/tetra/enrollment.env`
- `/etc/tetra/tetra.key`
- `/etc/tetra/tetra.crt`

Tetra no longer reads any of them (unless you pass the key and certificate to
the development `agent-ws-serve` listener yourself); the current enrollment
lives in `/var/lib/tetra/remote`. They can be deleted:

```sh
sudo rm -f /etc/tetra/enrollment.json /etc/tetra/enrollment.env \
  /etc/tetra/tetra.key /etc/tetra/tetra.crt
```

Keep `/etc/tetra/tetra.json`, which is the runtime config. A host enrolled the
old way has no outbound enrollment, so run `tetra enroll` again if it should be
remotely controlled.

### `unrecognized subcommand 'agent-ws-serve'`

The TCP listener is development-only and is compiled only with the
`dev-listener` feature. Build with `cargo run --features dev-listener -- ...`.
Release builds intentionally leave it out; local clients use the Unix socket
at `/run/tetra/tetra.sock`.

### `agent-ws-serve` refuses to bind to a non-loopback address

Non-loopback addresses require TLS. Provide both `--tls-cert` and `--tls-key`:

```sh
cargo run --features dev-listener -- agent-ws-serve \
  --listen 0.0.0.0:7780 \
  --tls-cert /etc/tetra/tetra.crt \
  --tls-key /etc/tetra/tetra.key \
  --controller-public-key "$TETRA_CONTROLLER_PUBLIC_KEY"
```

### Host identity is not generated

The host Ed25519 identity is auto-generated on first start and persisted under
`/var/lib/tetra/identity` by default. Tetra runs as root and keeps
`/var/lib/tetra` root-only (`0700`); ensure the directory is writable by root:

```sh
sudo mkdir -p /var/lib/tetra/identity
sudo chown -R root:root /var/lib/tetra
sudo chmod 0700 /var/lib/tetra
```

`--identity-dir` (on `agent-serve` and `agent-ws-serve`) overrides the default
path. The `TETRA_IDENTITY_DIR` environment variable is not read.

## WebSocket authentication (development listener)

These only apply to `agent-ws-serve` (`dev-listener` feature). The local socket
uses session tokens ([auth-protocol.md](auth-protocol.md)) and the outbound
session uses mTLS.

### Inbound connections fail with "missing controller public key"

`agent-ws-serve` requires an enrolled controller Ed25519 public key before it
will accept commands. Pass it on startup:

```sh
cargo run --features dev-listener -- agent-ws-serve \
  --listen 127.0.0.1:7780 \
  --controller-public-key "$TETRA_CONTROLLER_PUBLIC_KEY"
```

### Commands are rejected with "stale timestamp" or "duplicate nonce"

The authenticated WebSocket protocol enforces:
- Timestamp skew ≤ 5 minutes.
- Nonce replay protection per session.

Ensure the host and dashboard clocks are synchronized (e.g. NTP). If testing
across VMs, check that guest time is correct.

### Elevation grant expires too quickly

Password elevation only exists on `agent-ws-serve`. A grant lasts 30 minutes;
the duration is fixed. It is cleared when the session disconnects or Tetra
restarts. On the local socket there is no elevation: privileged actions are
authorized per request from the user's admin status and grants.

## Recipe rendering

### `render` fails with "failed to read template"

Template paths in the recipe are relative to `--templates-dir`. Verify that the
template file exists under that directory:

```sh
ls "${TEMPLATES_DIR}/containers/my-app.container.tera"
```

### Rendered filenames contain literal `{{ ... }}`

Filename fields are rendered through Tera. If you see raw template syntax in the
output, the parameter key is missing from the context. Ensure:
- The parameter is declared in `parameters`.
- A value, default, or `generate` strategy is provided.

### `choice` parameter fails validation

A `choice` parameter must define at least one option:

```yaml
parameters:
  - key: protocol
    type: choice
    options:
      - https
      - http
```

### Recipe validation rejects duplicate keys

Parameter `key` values must be unique within a recipe. Check for accidental
duplicates, including parameters that differ only in `label`.

## SELinux

### Files created by Tetra are not labeled correctly

Modules that manage paths accept a shared `selinux` payload. Ensure the
controller includes it when calling actions that create or modify files:

```json
{
  "id": "cmd-1",
  "module": "samba",
  "action": "set_config",
  "payload": {
    "contents": "[media]\npath = /srv/media\n",
    "selinux": {
      "path": "/srv/media",
      "context_type": "samba_share_t",
      "recursive": true
    }
  }
}
```

If `selinux` is omitted, the module will not relabel paths automatically. You
can run `restorecon` manually afterward.

### `semanage` is not available

The `selinux` module depends on `policycoreutils-python-utils` (or the
platform-equivalent package providing `semanage` and `restorecon`).

```sh
sudo dnf install policycoreutils-python-utils
```

## Queue and backpressure

### Dashboard receives `queue_full`

The bounded dispatch queue has a default capacity of 64 commands, and runs
them one at a time. If the host is processing a slow mutation (e.g. an image
pull during `systemctl start`), new commands are rejected until space frees
up. The local socket answers `queue_full`; the outbound WSS session sends an
`error` frame (`Tetra command queue is full; retry after backoff`).

Recommended responses:
- Retry with exponential backoff.
- Avoid flooding the agent with parallel mutating requests; the queue
  intentionally serializes host mutations.

### An action fails after 15 minutes with "failed to run"

Every host command a module runs is killed, with its process group, after 15
minutes (`COMMAND_TIMEOUT`), so a hung `systemctl`, `podman` or `virsh` cannot
block the queue forever. Check the unit or tool on the host
(`systemctl status`, `journalctl -u`) and retry.

### Commands time out but still execute

The queue worker sends the response through a oneshot channel. If the caller
times out or disconnects before receiving the response, the command still ran.
Use command IDs for idempotency and reconciliation rather than relying solely on
 the transport response.

## Vsock development

### `agent-vsock-serve` does not respond

Ensure the VM guest has virtio-vsock enabled and that you are connecting to the
correct CID and port:

```sh
# Find the guest CID (host-side)
virsh dumpxml VM_NAME | grep -A4 -i vsock

# Send a command
printf '%s' '{"id":"cmd-1","module":"settings","action":"get_system","payload":{}}' \
  | socat - VSOCK-CONNECT:GUEST_CID:2048
```

The vsock listener reads one command per connection and writes one JSON response.
It is a development smoke-test, not a production transport, and only exists in
builds with the `dev-listener` feature (`cargo run --features dev-listener --
agent-vsock-serve`).

## Network changes

### A network change was rolled back, or `network.confirm` fails

A `network.configure` or `network.connect_wifi` change that cut the host off
needs `network.confirm` within 60 seconds (see `network` in
[agent-protocol.md](agent-protocol.md)). Tetra arms that rollback as a
NetworkManager checkpoint, so NetworkManager rolls back even if Tetra is
stopped or restarting. `confirm` fails with "already rolled back" when it
arrives after that; `network.pending` (which survives Tetra restarts) shows
the token and the seconds left. To see checkpoints and the record Tetra
keeps:

```sh
busctl --json=short get-property org.freedesktop.NetworkManager \
  /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Checkpoints
sudo cat /var/lib/tetra/network/pending.json
journalctl -u NetworkManager | grep -i checkpoint
```

To keep a change by hand (for instance with Tetra down), destroy the
checkpoint and remove the record, or Tetra rolls the change back when it
starts:

```sh
sudo busctl call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
  org.freedesktop.NetworkManager CheckpointDestroy o /org/freedesktop/NetworkManager/Checkpoint/N
sudo rm /var/lib/tetra/network/pending.json
```

### "no NetworkManager checkpoint" in the journal

Tetra could not create a checkpoint: NetworkManager's D-Bus API is
unreachable (`busctl` missing, D-Bus down) or too old, or another checkpoint
(Cockpit's, or a stale one) already covers the device, which NetworkManager
refuses. Tetra then rolls back by itself, which a Tetra restart inside the
window delays until Tetra is back. List checkpoints as above; one left by
another tool rolls back or expires on its own.

## Logging and debugging

### Where Tetra logs

Tetra writes its messages to stderr, which systemd sends to the journal:

```sh
journalctl -u tetra.service
```

There is no log level to raise; `RUST_LOG` is not read. Module actions,
access changes and grant changes are also in the action log
(`admin.actions`, or `/var/lib/tetra/audit/actions.jsonl`).

### Dry-run before applying mutations

Most module actions support `dry_run: true`. Use it to preview changes without
modifying host state:

```json
{
  "id": "cmd-1",
  "module": "quadlets",
  "action": "install",
  "payload": {
    "scope": "system",
    "dry_run": true,
    "resources": [
      { "filename": "my-app.container", "contents": "..." }
    ]
  }
}
```

### One-shot local dispatch

The `agent-dispatch` CLI is the fastest way to test a module in isolation:

```sh
echo '{"id":"cmd-1","module":"settings","action":"get_system","payload":{}}' \
  | cargo run -- agent-dispatch
```

Or write the command to a file:

```sh
cargo run -- agent-dispatch examples/settings.command.json
```

## Getting more help

- Review the [agent protocol reference](agent-protocol.md) for frame shapes and action contracts.
- Review the [architecture overview](architecture.md) for how components interact.
- Check `examples/` for sample command envelopes and transport configs.
