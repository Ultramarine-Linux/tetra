# Tetra

Tetra is a modular host agent and recipe renderer for the [Ultramarine Server Dashboard](https://github.com/Ultramarine-Linux/dashboard).
It is organized around a single dispatcher with independent,
feature-gated modules for apps, files, recipes, SELinux, services, Quadlets,
reverse proxy (Caddy), Podman, Samba, NFS, users, storage, network, power,
updates, remote access (Tailscale, Cloudflare Tunnel), and virtual machines.
The `settings` module is always compiled so the control plane can discover
basic host facts.

Local clients (the dashboard container and the server OOBE) talk to Tetra over
a Unix socket at `/run/tetra/tetra.sock` (`agent-serve`). This is the only
listener a production install runs; Tetra does not listen on the network.
Tetra identifies the client from the socket's peer credentials and is the only
authority for login and authorization: users log in with a password (PAM) plus
TOTP, or a passkey, and every request after login carries a Tetra-issued
session token (login, setup-code redemption, the app access check and
`shell.open` take none; see the "no token" operations). See
[docs/auth-protocol.md](docs/auth-protocol.md).

An outbound mTLS WSS connection (`wss://` only) to a remote control plane also
exists. It is off unless `remote.enabled` is set in `/etc/tetra/tetra.json`.

For development, `agent-ws-serve` (the `dev-listener` feature) serves the
same Tetra session protocol as the Unix socket over loopback TCP. TCP has no
peer credentials, so `--client dashboard|oobe` (default `dashboard`) applies
to every connection; any local process can claim that client identity, but
still needs a valid Tetra session. It is dev-only and refuses non-loopback
binds. See [the session protocol](docs/auth-protocol.md#development-tcp-listener).

The local `agent-dispatch` command accepts the same command envelope shape for
one-shot debugging. See [docs/agent-protocol.md](docs/agent-protocol.md) for
the controller-facing API, connection negotiation, and agent protocol reference.

Recipes are declared in YAML, and Quadlet generation uses Tera templates. A
recipe declares metadata, UI parameters, requirements, and a list of resources
to render.

## Documentation

- [Agent protocol reference](docs/agent-protocol.md) — Connection negotiation, authentication, and the full module action catalog.
- [Session protocol](docs/auth-protocol.md) — Login, sessions, permissions and first-boot setup on the local socket.
- [Dashboard auth guide](docs/dashboard-auth-guide.md) — How the dashboard and OOBE should call Tetra for login and authorization.
- [Recipe authoring guide](docs/recipes.md) — How to write recipes, parameters, templates, and resources.
- [Architecture overview](docs/architecture.md) — Crate layout, dispatcher, queue, transports, and how to add a module.
- [Remote enrollment](docs/remote-enrollment.md) — The controller side of `tetra enroll` and the outbound mTLS connection.
- [Troubleshooting](docs/troubleshooting.md) — Common issues with TLS, identity, the development listener, recipe rendering, SELinux, and queue backpressure.

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
- `power`
- `updates`
- `remote-access`

Additional optional features:

- `virtual-machines`
- `dev-listener`: the development-only loopback TCP session listener
  (`agent-ws-serve`). Leave it off in release builds.
- `testing`: exposes `tetra::auth::testing` (fake PAM, accounts, sealer and
  host) for integration tests.

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

Run it (without a file it reads the command from stdin):

```sh
cargo run -- agent-dispatch examples/settings.command.json
```

`agent-dispatch` calls the modules directly, with no login, authorization or
action log, so use it only for local debugging.

`examples/apps.command.json` shows a dry-run `apps.create` that cooks an
inline recipe into an installed app bundle.

### Local socket (production)

`agent-serve` is the host agent daemon. It serves the session protocol
([docs/auth-protocol.md](docs/auth-protocol.md)) to local clients over a Unix
socket. Only the `ultramarine-dashboard` and `ultramarine-oobe` accounts may
connect (`--dashboard-user`/`--oobe-user`). Under systemd the socket comes
from `tetra.socket` through socket activation; otherwise Tetra binds
`--socket` (default `/run/tetra/tetra.sock`) with mode `0660`:

```sh
cargo run -- agent-serve \
  --socket /tmp/tetra.sock \
  --identity-dir /tmp/tetra-identity \
  --state-dir /tmp/tetra-state
```

Clients open a WebSocket over the Unix stream; the HTTP `Host` and path are
ignored. With Node's `ws`, use `ws+unix:///run/tetra/tetra.sock`.

### Loopback session server (development)

`agent-ws-serve` runs the host daemon on loopback TCP instead of the Unix
socket. It is only built with `dev-listener`; it uses the same `AuthService`,
PAM/TOTP or passkey login, session tokens, grants, and action log as
`agent-serve`. On a server, this normally means running it as root; the
example uses scratch state so it does not reuse the host's login database:

```sh
cargo build --features dev-listener
sudo target/debug/tetra agent-ws-serve \
  --listen 127.0.0.1:7780 --client dashboard \
  --identity-dir /tmp/tetra-identity --state-dir /tmp/tetra-state
```

`--client` accepts `dashboard` or `oobe` and defaults to `dashboard`. Since
TCP has no peer credentials, the selected client is applied to every
connection; any local process that reaches the port gets that client identity,
but every operation still needs what it needs on the socket (a valid Tetra
session, except the "no token" ones such as login). `--listen` rejects
non-loopback addresses. TLS is omitted because this
loopback-only development endpoint is not a remote transport and cannot replace
the process credentials of the Unix socket. Use the Unix socket in production.
See [docs/auth-protocol.md](docs/auth-protocol.md#development-tcp-listener)
for connection and frame details.

### Outbound WSS control plane (remote control)

Remote control ships disabled. `agent-serve` connects out only while
`remote.enabled` is `true` in the runtime config, `/etc/tetra/tetra.json`
(override with `--config` or `TETRA_CONFIG`). A missing file means remote
control is off, and an unreadable or invalid file turns it off too.

After [`tetra enroll`](#host-enrollment), the gate is all the config needs; the
host id, control-plane URL and mTLS material come from the enrollment:

```json
{ "remote": { "enabled": true } }
```

`remote.host_id` and `remote.transport` override the enrollment when set:

```json
{
  "remote": {
    "enabled": true,
    "host_id": "host-01",
    "transport": {
      "control_plane_url": "wss://dashboard.example.com/tetra/agent",
      "client_cert_path": "/var/lib/tetra/remote/client.crt",
      "client_key_path": "/var/lib/tetra/remote/client.key",
      "server_ca_path": "/var/lib/tetra/remote/server-ca.crt"
    }
  }
}
```

`examples/tetra.json` has the full shape. Tetra re-reads the file on `SIGHUP`
(`systemctl reload tetra.service`). Enabling remote control starts the mTLS
session; disabling it drops any live session immediately. A reload that
leaves `remote` unchanged keeps the current session.

`agent-connect` runs the same outbound session on its own. It uses the
enrollment by default; `--config` (a transport file) and `--host-id` override
it. It obeys the same gate: it refuses to start unless `remote.enabled` is
`true`, and it drops the session when a `SIGHUP` reload turns it off or finds
the enrollment removed:

```sh
cargo run -- agent-connect --runtime-config examples/tetra.json
cargo run -- agent-connect --config examples/transport.json --host-id myhost \
  --runtime-config examples/tetra.json
```

## Systemd

`systemd/tetra.socket` creates `/run/tetra/tetra.sock` as `root:tetra`, mode
`0660`, and socket-activates `systemd/tetra.service`, which runs
`agent-serve` and persists identity under `/var/lib/tetra/identity` and login
state under `/var/lib/tetra` (root only). The service does not bind a TCP port.
`systemd/tetra-setup-code.service` shows the first-boot setup code on the
console until setup completes. `pam/ultramarine-dashboard` is the PAM service
used for dashboard passwords and `pam/tetra-shell` the one web shells run
(`agent-serve --shell-pam-service`); both belong in `/etc/pam.d`.

`systemd/tetra.sysusers.conf` creates the `tetra` group with the fixed GID
**241**, chosen from Fedora's system range (201–999) outside the 0–200 range
the `setup` package reserves. The dashboard's rootful container must keep the
host UID of `ultramarine-dashboard` and receive the group by number: in its
Quadlet, `Volume=/run/tetra/tetra.sock:/run/tetra/tetra.sock` and
`GroupAdd=241`. The OOBE service uses `SupplementaryGroups=tetra`. A host whose
`tetra` group already existed with another GID keeps it (`systemd-sysusers`
does not change existing groups, and falls back to a dynamic GID if 241 is
taken); `agent-serve` logs a warning in that case, and the group has to be
fixed with `groupmod -g 241 tetra`.

### The apps account

User apps run rootless under one system account, `ultramarine-apps`, which
`systemd/tetra.sysusers.conf` also creates, with the fixed UID and GID
**242** (same range and reasoning as the `tetra` group) and the home
`/var/lib/ultramarine-apps`. It cannot log in: no password, `nologin` shell,
and Tetra refuses it as a dashboard user. Packaging:

- Install `systemd/tetra.sysusers.conf` as
  `/usr/lib/sysusers.d/tetra.conf` and `systemd/tetra.tmpfiles.conf` as
  `/usr/lib/tmpfiles.d/tetra.conf` (`%sysusers_create_compat` and
  `%tmpfiles_create` in the spec; bootc images apply both at boot).
  `systemd-sysusers` only records the home, so the tmpfiles snippet creates
  it (`0700`, owned by the account).
- **Linger.** The tmpfiles snippet also creates
  `/var/lib/systemd/linger/ultramarine-apps`, which is what
  `loginctl enable-linger` records: logind starts the account's user manager
  at boot, so app services run without a login. Tetra runs
  `loginctl enable-linger` itself if the flag is missing.
- **Subordinate IDs.** Rootless Podman needs `/etc/subuid` and `/etc/subgid`
  ranges, which `systemd-sysusers` does not allocate (and `useradd -r` only
  does with `-F`). Tetra adds them on the first `apps.create`/`update` that
  converges: the first free 65536 IDs from 524288 (Fedora's
  `SUB_UID_MIN`/`SUB_UID_COUNT`), with `usermod --add-subuids FIRST-LAST
  --add-subgids FIRST-LAST ultramarine-apps`, skipped when the account (by
  name or UID) already has a range. Doing it at runtime rather than in a
  scriptlet keeps it right on bootc, where `/etc` is per machine and the
  account only exists after the first boot.
- **SELinux.** A home under `/var/lib` gets none of the `HOME_DIR` rules that
  label rootless storage in `/home`, so Tetra adds `semanage fcontext -a -e
  /var/lib/containers/storage
  /var/lib/ultramarine-apps/.local/share/containers/storage` unless
  `file_contexts.subs` already has it, creates the storage and relabels it
  with `restorecon -R`, once (recorded in
  `/var/lib/tetra/apps-storage-labels`). Images may apply the same rule at
  build time instead.
- `agent-serve` logs a warning when the account is missing or its UID/GID is
  not 242 (`usermod -u 242 -g 242` fixes it; files in the home must then be
  re-owned).

Apps installed by earlier releases are system-scope (rootful) and keep
working with `"scope": "system"`; Tetra does not migrate them. See the
`apps` section of [docs/agent-protocol.md](docs/agent-protocol.md).

## Host enrollment

Remote control is outbound only: the host dials the controller over WSS and
authenticates with an mTLS client certificate. Nothing listens on the network
and no inbound address is registered.

`tetra enroll` obtains that certificate with a device authorization flow:

1. Tetra checks that `remote.enabled` is `true` in `/etc/tetra/tetra.json`
   and refuses to run otherwise. It also refuses if the host is already
   enrolled.
2. It generates a fresh ECDSA P-256 key pair and a certificate signing request
   with the `clientAuth` extended key usage. The private key never leaves the
   host.
3. It sends the CSR to the controller, prints a verification URL and a short
   approval code, and waits for an administrator to approve the request.
4. On approval the controller signs the CSR and returns the client
   certificate, the CA bundle for its WSS endpoint, the host id and the
   `wss://` control-plane URL. Tetra checks that the certificate is for its
   key, allows `clientAuth` and is currently valid.
5. Tetra stores everything root-only under `/var/lib/tetra/remote`
   (directory `0700`, files `0600`) and reloads `tetra.service`, which then
   connects out.

```sh
tetra enroll --dashboard-url https://control.example.com --display-name host-01
```

| File                                    | Contents                                        |
| --------------------------------------- | ----------------------------------------------- |
| `/var/lib/tetra/remote/client.key`      | Client private key, generated on the host.      |
| `/var/lib/tetra/remote/client.crt`      | Client certificate signed by the controller.    |
| `/var/lib/tetra/remote/server-ca.crt`   | CA bundle that verifies the controller's WSS.   |
| `/var/lib/tetra/remote/controller.json` | Host id, control-plane URL and enrollment URL.  |

The controller URL must use `https://`, because the server CA is delivered over
that connection. `--insecure` allows `http://` and invalid TLS for local
development only. `--skip-service` skips the `systemctl` calls, for containers
and the OOBE. `--enrollment-dir` (or `TETRA_ENROLLMENT_DIR`) changes the
storage directory for `enroll`, `unenroll`, `agent-serve` and `agent-connect`.

Setting `remote.enabled` back to `false` (and reloading) stops the connection
but keeps the enrollment, so turning it on again reconnects without
re-enrolling. To remove the enrollment, run:

```sh
tetra unenroll
```

This deletes the client key, certificate, server CA and controller record and
reloads `tetra.service`, which drops any live session. It works whether or not
remote control is enabled. It does not contact the controller; remove or
revoke the host there as well.

The controller-side API is described in
[docs/remote-enrollment.md](docs/remote-enrollment.md).

## Authentication and Authorization

Local clients authenticate users through Tetra and send a session token with
every request after login (the "no token" operations aside); Tetra authorizes each action from the user's admin status
(`ultramarine-admin` or `wheel`) and per-page grants. See
[docs/auth-protocol.md](docs/auth-protocol.md). Outbound WSS uses mTLS for
transport identity, with the client certificate issued by `tetra enroll`; its
commands run with full rights, always as root, and are recorded as remote
actions. Commands are not signed on either production transport. The
development TCP listener uses the same Tetra-issued session protocol as the
Unix socket.

Console recovery: `sudo tetra auth reset-2fa <user>` removes a user's TOTP and
recovery codes, and `sudo tetra setup code` prints the first-boot setup code. On a host that
already has an eligible administrator, `sudo tetra setup complete` finishes
setup without the OOBE.

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
