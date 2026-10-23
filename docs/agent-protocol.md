# Tetra Agent Protocol

This document describes the JSON command envelope used by the Tetra host
agent. The local CLI command `tetra agent-dispatch` accepts the same envelope
that module transports carry.

## Connection Negotiation

Local clients (the dashboard container and the server OOBE) connect to Tetra
over the Unix socket `/run/tetra/tetra.sock` (`tetra agent-serve`) and speak the
session protocol described in [auth-protocol.md](auth-protocol.md): users log
in through Tetra and each request carries a session token. Module commands are
sent with the `module.dispatch` operation using the envelope documented below.
Production installs do not listen on the network.

For local development, `agent-ws-serve` (built with `--features dev-listener`)
serves the same WebSocket session protocol on loopback TCP. Build it and run
with the same privileges and PAM setup as the daemon (usually root):

```sh
cargo build --features dev-listener
sudo target/debug/tetra agent-ws-serve \
  --listen 127.0.0.1:7780 --client dashboard
```

`--listen` refuses non-loopback addresses. TCP has no peer credentials, so
`--client dashboard|oobe` (default `dashboard`) is applied to every
connection; any local process can claim that client. The listener uses the
same Tetra-issued session tokens and `AuthService` as the Unix socket.
It is development-only and has no TLS. See
[auth-protocol.md](auth-protocol.md#development-tcp-listener).

An outbound connection to a remote control plane is optional and ships
disabled. It runs only while `remote.enabled` is `true` in
`/etc/tetra/tetra.json`, and turning it off drops a live session. It is WSS
with mTLS, run by `tetra agent-serve` when `remote.enabled` is set, or
standalone via `tetra agent-connect`. The JSON command envelope documented
below is the stable application payload that the transport carries.

Transport configuration:

```json
{
  "control_plane_url": "wss://dashboard.example.com/tetra/agent",
  "client_cert_path": "/var/lib/tetra/remote/client.crt",
  "client_key_path": "/var/lib/tetra/remote/client.key",
  "server_ca_path": "/var/lib/tetra/remote/server-ca.crt"
}
```

Fields (all required):

- `control_plane_url`: Endpoint the agent connects to. Must be `wss://`;
  any other scheme is refused.
- `client_cert_path`: Agent client certificate for mTLS.
- `client_key_path`: Private key for the client certificate.
- `server_ca_path`: CA bundle used to verify the dashboard/control-plane server
  certificate.

The same fields can be set as `remote.transport` in `/etc/tetra/tetra.json`.
Without them, Tetra uses the enrollment written by `tetra enroll`.

Run the outbound agent. After `tetra enroll` no flags are needed; `--config`
and `--host-id` override the enrollment:

```sh
tetra agent-connect
tetra agent-connect --config /etc/tetra/agent-transport.json --host-id host-01
```

### Recommended Lifecycle

1. `enroll`: `tetra enroll` (only while `remote.enabled` is true) sends a CSR
   with the `clientAuth` extended key usage. After approval the controller
   returns the signed client certificate, its server CA, a stable host id and
   the `wss://` URL. See [remote-enrollment.md](remote-enrollment.md).
2. `connect`: The agent opens `control_plane_url` with mTLS, and the
   dashboard verifies the client certificate.
3. `hello`: Immediately after WSS open, the agent sends a small hello frame with
   agent metadata. The dashboard uses this to mark the host online.
4. `capabilities`: The dashboard sends `agent.capabilities` as its first
   command or relies on a capabilities frame in the hello response. The
   dashboard should cache the enabled module/action set per connection.
5. `dispatch`: The dashboard sends one `AgentCommand` per requested operation.
   The agent replies with the matching `AgentResponse.id`.
6. `heartbeat`: The agent and dashboard exchange pings or heartbeat frames so
   stale connections can be closed.
7. `reconnect`: On disconnect, the agent reconnects with backoff and repeats
   hello/capability negotiation.
8. `renew`: At two-thirds of its client certificate's lifetime, the agent
   sends a `renew` frame with a new CSR. The controller answers `renewed` or
   `renew_failed`, and the agent reconnects with the new certificate. See
   [remote-enrollment.md](remote-enrollment.md#certificate-renewal).

### Transport Frames

A simple frame format is enough for the first WSS implementation:

```json
{
  "type": "hello",
  "host_id": "host-01",
  "agent_version": "0.1.0",
  "protocol_version": "2026-10-18",
  "hostname": "fedora-server",
  "os": "linux",
  "arch": "x86_64"
}
```

Command frame:

```json
{
  "type": "command",
  "command": {
    "id": "cmd-001",
    "module": "settings",
    "action": "get_system",
    "payload": {}
  }
}
```

Response frame:

```json
{
  "type": "response",
  "response": {
    "id": "cmd-001",
    "ok": true,
    "payload": {
      "os": "linux",
      "arch": "x86_64",
      "family": "unix"
    }
  }
}
```

Heartbeat frame:

```json
{
  "type": "ping",
  "id": "ping-001",
  "sent_at": "2026-06-29T12:00:00Z"
}
```

The matching heartbeat response can be:

```json
{
  "type": "pong",
  "id": "ping-001",
  "sent_at": "2026-06-29T12:00:00Z"
}
```

### Dashboard Addressing Model

The dashboard should route commands by host id, not by network address. A
typical internal model is:

```json
{
  "host_id": "host-01",
  "display_name": "fedora-server",
  "connection_state": "online",
  "last_seen_at": "2026-06-29T12:00:00Z",
  "capabilities": {
    "modules": []
  }
}
```

When a user clicks an action in the dashboard:

1. Find the active WSS connection for `host_id`.
2. Generate a unique command `id`.
3. Send a `command` frame containing the `AgentCommand`.
4. Wait for a `response` frame with the same `id`.
5. Update UI state from `ok`, `payload`, or `error`.

If the host is offline, the dashboard may either reject the request immediately
or queue only explicitly safe operations. For host-mutating actions, prefer not
to queue commands across reconnects unless the user explicitly confirms that
behavior.

### Authentication And Authorization

Use mTLS for transport identity:

- Dashboard/server certificate is validated by the agent using `server_ca_path`.
- Agent/client certificate is validated by the dashboard.
- The dashboard maps the client certificate identity to exactly one host id.

On the host, an mTLS session is authorized as the remote controller, which may
run every module action, including payload fields that are administrator-only
on the local socket. Tetra records each remote action in its action log with
`origin: "remote"` and the host id. The `user` field of a command from the
control plane is ignored, so remote commands run as root, except reads of a
module whose default is the apps account (`podman`, see
[Run As](#run-as)), which run as `ultramarine-apps` unless the payload says
`"run_as": "root"`.

Use command authorization separately from transport authentication:

- Only authorized dashboard users should be able to create commands.
- Dangerous actions should require explicit UI confirmation.
- Prefer a dry-run preview before sending a mutating command without
  `"dry_run": true`.
- Record the dashboard user, command id, host id, module, action, payload hash,
  and response outcome in an audit log.

Commands are not signed: the mTLS session is what authenticates them.

### Reconnect And Idempotency

Agents should reconnect with bounded exponential backoff and jitter. On each
new connection, the dashboard should treat in-flight command ids from the old
connection as unknown unless it has received a response.

Controller guidance:

- Generate globally unique command ids, such as ULIDs or UUIDs.
- Treat command responses as at-most-once from the current connection.
- Make mutating workflows explicit and visible to the user.
- Use `dry_run: true` to preview host command plans.
- Re-fetch capabilities after every reconnect.

Commands run one at a time on the host. When Tetra's queue is full it answers
with an `error` frame (`Tetra command queue is full; retry after backoff`)
instead of a `response`; retry with backoff. A host command that runs longer
than 15 minutes is killed and its action fails.

## Protocol Contract

All requests are single-command JSON envelopes:

```json
{
  "id": "cmd-001",
  "module": "settings",
  "action": "get_system",
  "payload": {},
  "signature": null
}
```

Fields:

- `id`: Controller-generated correlation id. The response echoes this value.
- `module`: Module name, such as `settings`, `services`, or `quadlets`.
- `action`: Module-specific action.
- `payload`: Action-specific object. Defaults to `null` when omitted, which
  every action reads as `{}`: actions that take no payload, or whose fields
  all have defaults (such as `power.reboot` or `remote_access.tailscale_disable`
  with `dry_run`), accept it. Like unknown fields elsewhere, the fields of an
  object given to an action that takes no payload are ignored.
- `signature`: Optional and ignored, except that an empty string is rejected.
  Commands are not signed or verified on the local socket or the WSS session.
- `user`: Set by Tetra, not the caller. On the local socket it is the
  session's user, so unprivileged actions run as that user; in commands from
  a remote controller it is cleared, so they run as root.

Responses always have this shape:

```json
{
  "id": "cmd-001",
  "ok": true,
  "payload": {}
}
```

Errors return `ok: false` and an `error` string:

```json
{
  "id": "cmd-001",
  "ok": false,
  "error": "unknown module `missing`"
}
```

Controllers should treat a response as failed when `ok` is false, even if the
transport succeeded.

## Discovery

Use dispatcher capabilities to discover enabled modules and actions:

```json
{
  "id": "cmd-capabilities",
  "module": "agent",
  "action": "capabilities",
  "payload": {}
}
```

Response payload:

```json
{
  "modules": [
    {
      "name": "settings",
      "feature": "core",
      "description": "Agent and host settings that are always available.",
      "status": "available",
      "actions": ["capabilities", "get_system", "set_hostname", "set_keymap", "set_locale", "set_timezone"],
      "privileged_actions": ["set_hostname", "set_keymap", "set_locale", "set_timezone"]
    }
  ]
}
```

Every module also supports:

- `capabilities`: Returns that module's `ModuleInfo`.
- `plan`: Returns `{module, feature, status, requested}`, echoing the
  payload. This is a lightweight planning endpoint, not a dry-run replacement.

Both are answered by the dispatcher for every module, whether or not the
module's `actions` lists them.

## Shared Conventions

### Run As

Unprivileged actions (reads such as `podman.containers`,
`virtual_machines.list` or `selinux.booleans`) run their host commands as the
signed-in user, so a user sees their own session VMs, except in `podman`,
whose reads run as `ultramarine-apps`, the account every user app runs under
(see [apps](#apps)), so the Containers page shows the apps' containers.
Privileged actions always run as root. An unprivileged action's payload may
add `"run_as"`:

- `"user"`: as the signed-in user (the default, except in `podman`).
- `"apps"`: as `ultramarine-apps` (the default in `podman`).
- `"root"`: as root, showing the host's view (rootful containers, every VM).
- `"both"`: runs the action as the signed-in user and as root, and returns
  `{"user": {"ok": true, "result": ...}, "root": {"ok": false, "error": "..."}}`.
  Refused for privileged actions and when there is no signed-in user.

Tetra switches users with `runuser -u <user> --`, setting `XDG_RUNTIME_DIR`
to `/run/user/<uid>` when that user's manager runs (so rootless Podman and
`systemctl --user` find it; the apps account's lingers). Which `run_as` a
module uses without one is its `Mod::default_run_as`; the dispatcher applies
it, so modules never pick users themselves.

`run_as` is removed from the payload before the module sees it. `"root"` and
`"both"` are administrator-only; `"user"` and `"apps"` are open to anyone
who may run the action. Commands from the remote controller, the setup
session and the `agent-dispatch` CLI have no user and run as root (as
`ultramarine-apps` in `podman`).

### Dry Run

Mutating actions execute by default. Include `"dry_run": true` in the action
payload to return the command or write plan without changing the host.

Dry-run command response shape:

```json
{
  "command": "systemctl restart example.service",
  "status": null,
  "stdout": "",
  "stderr": "",
  "dry_run": true
}
```

Executed command response shape:

```json
{
  "command": "systemctl restart example.service",
  "status": 0,
  "stdout": "",
  "stderr": "",
  "dry_run": false
}
```

### SELinux Options

Modules that create or manage files/paths can accept a shared `selinux` object:

```json
{
  "selinux": {
    "enabled": true,
    "path": "/srv/media",
    "path_pattern": "/srv/media(/.*)?",
    "context_type": "samba_share_t",
    "recursive": true
  }
}
```

Fields:

- `enabled`: Optional boolean. Useful when a caller wants only `restorecon`.
- `path`: Path to relabel. If omitted, the module may use its managed path.
- `path_pattern`: Exact `semanage fcontext` pattern. If omitted and
  `context_type` is set, the agent derives it from `path`; recursive paths use
  `PATH(/.*)?`.
- `context_type`: SELinux type passed to `semanage fcontext -a -t`.
- `recursive`: Adds `-R` to `restorecon` and affects default `path_pattern`.

Actions that support this shared object include:

- `apps.create`
- `apps.update`
- `files.write`
- `quadlets.write`
- `quadlets.install`
- `storage.mount`
- `storage.configure`
- `samba.set_config`
- `nfs.set_config`

`network.set_config` always relabels the keyfile with its default context and
rejects `path`, `path_pattern` and `context_type`.

SELinux operation responses are returned as a `selinux` array of command result
objects.

## Common Command Result

Many command-backed actions return:

```json
{
  "command": "podman ps --all --format json",
  "status": 0,
  "stdout": "...",
  "stderr": "",
  "dry_run": false
}
```

Some read actions also parse `stdout` into a stable JSON field, such as `data`,
`services`, `domains`, `domain`, `booleans`, or `file_contexts`.

## Modules

The enabled module set depends on build features. Default features are
`apps`, `files`, `recipes`, `selinux`, `services`, `quadlets`,
`reverse-proxy`, `podman`, `samba`, `nfs`, `users`, `storage`, `network`,
`power`, `updates` and `remote-access`; `virtual-machines` is optional.
`settings` is always compiled.

Actions listed as privileged (`privileged_actions` in `capabilities`) always
run as root. The others run as the session's user (through `runuser`) on the
local socket, and as root for remote controllers and the setup session,
unless `run_as` or the module's default says otherwise (see
[Run As](#run-as)).

Payload values that become positional arguments of a host command (service,
container, VM and account names, paths given to `df`, `umount`, `mount`,
`restorecon` or `semanage`, and the like) may not be empty or start with `-`,
so they can never be read as an option. Unknown payload fields are ignored
unless a section says otherwise.

Request payloads are plain JSON objects. Payload types shared across modules —
such as `SelinuxOptions`, `ServiceScope`, `AppScope`, and the `apps` module's
`App*` requests — are defined in `src/types/` and deserialized with `serde`.

### settings

Always available.

Actions:

- `get_system`
- `set_hostname` (privileged)
- `set_keymap` (privileged)
- `set_locale` (privileged)
- `set_timezone` (privileged)

Request:

```json
{ "module": "settings", "action": "get_system", "payload": {} }
```

Payload response:

```json
{
  "os": "linux",
  "arch": "x86_64",
  "family": "unix"
}
```

The setters return the command result and accept `dry_run`:

- `set_hostname` `{ "hostname": "server" }` runs `hostnamectl set-hostname`.
- `set_keymap` `{ "layout": "de", "variant": "nodeadkeys" }` runs
  `localectl set-x11-keymap`, which also sets the console keymap. `layout`
  (comma-separated for several) and the optional `variant` are 1–64 letters,
  digits, `_`, `-` or `,`.
- `set_locale` `{ "locale": "de_DE.UTF-8" }` sets `LANG` with
  `localectl set-locale`. Locales start with a letter and contain letters,
  digits, `_`, `.`, `-` or `@`.
- `set_timezone` `{ "timezone": "Europe/Berlin" }` runs
  `timedatectl set-timezone` with an IANA name: a letter first, then letters,
  digits, `_`, `-`, `+` or `/`, no `..` and no trailing `/`.

### files

Feature: `files`

Actions:

- `read`
- `write` (privileged)

`read` payload:

```json
{ "path": "/etc/example.conf" }
```

`read` returns `{path, contents}`. Both actions only accept a regular file:
a FIFO, device, socket or directory is refused (without blocking on it).
`read` refuses files larger than 16 MiB and files that are not UTF-8.
`write` creates the file if needed and otherwise replaces its contents in
place, keeping its owner, mode and SELinux label.

`write` payload:

```json
{
  "path": "/etc/example.conf",
  "contents": "enabled=true\n",
  "dry_run": true,
  "selinux": {
    "context_type": "etc_t"
  }
}
```

`write` response payload:

```json
{
  "path": "/etc/example.conf",
  "written": false,
  "dry_run": true,
  "selinux": []
}
```

### recipes

Feature: `recipes`

Actions:

- `render`
- `render_inline`
- `context`
- `context_inline`

`render` and `render_inline` accept `source: {catalog: "official"|"community"|"custom",
url?, sha256}` and `allow_unpinned_images: false`. The digest covers exact recipe
and template bytes using the [canonical v1 algorithm](recipes.md#canonical-bundle-digest-v1).
Omitted source means custom with pinning enforced. Only custom may explicitly
opt out; official/community opt-out and any digest mismatch are errors before
writes, including dry runs. Responses include verified `source` metadata and
the computed digest. Context actions are unchanged. No catalog fetching occurs.
See [image policy and limitations](recipes.md#rendered-image-policy).

`render` payload:

```json
{
  "recipe_path": "schema.yaml",
  "templates_dir": "./templates",
  "values_path": "examples/nextcloud.values.yaml",
  "output_dir": "./quadlets",
  "dry_run": true
}
```

Response payload:

```json
{
  "resources": [
    {
      "kind": "Container",
      "filename": "nextcloud-app.container",
      "contents": "[Container]\n..."
    },
    {
      "kind": "File",
      "filename": "index.html",
      "contents": "<h1>Hello</h1>\n"
    }
  ]
}
```

Recipe resource kinds include Quadlet resources (`container`, `network`,
`volume`, `image`, `pod`, `kube`) and `file` companion resources. Companion file
resources are intended to be installed through `quadlets.install.files`, under
the mutable companion-file bundle directory.

`render_inline` payload:

```json
{
  "recipe": "recipe_id: nginx-site\nname: Nginx static site\nversion: 0.1.0\n...",
  "templates": {
    "containers/nginx-site.container.tera": "[Container]\nContainerName={{ app_id }}\nImage=docker.io/library/nginx:alpine@sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417\n"
  },
  "values": {
    "app_id": "demo-web"
  }
}
```

The response holds the parsed `recipe`, rendered `resources`, and verified `source`.
`render_inline` writes nothing.

This action is intended for recipe bundles fetched from a remote catalog by a
dashboard or control plane. Tetra does not need to be updated when new recipes
are published, as long as the bundle uses a recipe schema the installed Tetra
version understands.

Recommended remote catalog shape:

```json
{
  "version": 1,
  "recipes": [
    {
      "id": "nginx-site",
      "name": "Nginx static site",
      "description": "Serve static files with nginx.",
      "category": "web",
      "recipe": "recipe_id: nginx-site\n...",
      "templates": {
        "containers/nginx-site.container.tera": "[Container]\n..."
      }
    }
  ]
}
```

`context_inline` accepts the same `recipe` and `values` fields as
`render_inline` (no `templates`), and returns the parsed `recipe` and the
resolved parameter `context` without rendering templates.

`render` and `context` read the recipe, templates and values from host paths,
and `render` writes to `output_dir` unless `dry_run` is set, so both are
administrator-only on the local socket, as is `render_inline` (a template can
loop for a very long time on the one-at-a-time queue). Only `context_inline`
can be granted.

`context` payload:

```json
{
  "recipe_path": "schema.yaml",
  "values": {
    "domain": "cloud.example.test"
  }
}
```

Response payload contains a `context` object with recipe metadata and resolved
parameter values.

### quadlets

Feature: `quadlets`

Actions:

- `list`
- `read`
- `write` (privileged)
- `delete` (privileged)
- `validate`
- `install` (privileged)
- `list_files`

Shared payload fields:

- `scope`: `"apps"` (the default) or `"system"`, as in `apps`. Apps scope is
  the rootless Quadlets of the `ultramarine-apps` account, whoever is signed
  in; system scope is rootful, for real system services. The `"user"` scope
  of earlier releases (the signed-in user's home) is gone and refused: user
  apps belong to the shared apps account, not to whoever installed them.
- `base_dir`: Optional override. Useful for tests and custom deployments.
- `files_base_dir`: Optional override for companion files.

Default Quadlet unit directories:

- Apps scope: `~ultramarine-apps/.config/containers/systemd`
  (`/var/lib/ultramarine-apps/...`; the home comes from the account database)
- System scope: `/etc/containers/systemd`

Default companion file directories:

- Apps scope: `~ultramarine-apps/.local/share/tetra/quadlets`
- System scope: `/var/lib/tetra/quadlets`

During `install`, companion files are written under a per-Quadlet bundle directory
derived from the first Quadlet resource name. For example, `app.container` companion
files default to `~ultramarine-apps/.local/share/tetra/quadlets/app` in apps
scope and `/var/lib/tetra/quadlets/app` in system scope.

In apps scope, every file and directory Tetra writes below the account's home
is handed to `ultramarine-apps` (`lchown` after the atomic write; modes stay
`0600` for units and `0644` for companions, directories are `0755` and the
home `0700`), and the `write` and `install` responses say so with
`"owner": "ultramarine-apps"` (`"root"` in system scope). The home and every
directory below it are refused if one is a symlink, since the account (and
so an app container's root) owns that tree. Without root (tests, development)
files keep their owner. `quadlets` only writes files: run
`services.daemon_reload` with `"scope": "apps"` afterwards, and use
`apps.create` (which also prepares the account, see [apps](#apps)) to install
apps.

Supported Quadlet filename extensions:

- `.container`
- `.kube`
- `.network`
- `.pod`
- `.volume`

`list` payload:

```json
{ "scope": "apps" }
```

`write` payload:

```json
{
  "scope": "system",
  "filename": "app.container",
  "contents": "[Container]\nImage=example/app:latest\n",
  "dry_run": true,
  "selinux": {
    "context_type": "container_unit_file_t"
  }
}
```

`install` payload:

```json
{
  "scope": "system",
  "dry_run": true,
  "resources": [
    {
      "filename": "app.container",
      "contents": "[Container]\nImage=example/app:latest\n"
    }
  ],
  "files": [
    {
      "filename": "index.html",
      "contents": "<h1>Hello</h1>\n"
    },
    {
      "filename": "nginx/default.conf",
      "contents": "server {}\n"
    }
  ],
  "selinux": {
    "context_type": "container_unit_file_t",
    "recursive": true
  }
}
```

`resources` are validated as Quadlet files and written to the Quadlet unit directory.
`files` are companion files written under the mutable companion-file bundle directory,
support nested relative paths, and are rejected if the path escapes the bundle directory.

Validation (`validate`, `write`, `install`) checks the extension, that the
contents are not empty, and that they contain a Quadlet section header
(`[Container]`, `[Kube]`, `[Network]`, `[Pod]` or `[Volume]`); it is not a
full `quadlet -dryrun`. Files are written atomically, unit files with mode
`0600` (they can hold secrets) and companion files `0644`. A path that is
absolute, contains `..` or passes through a symlink below the base directory
is refused by `read`, `write`, `delete` and `install`.

`list_files` payload:

```json
{ "scope": "apps" }
```

`list_files` returns all regular files under the selected base directory, including
companion files:

```json
{
  "base_dir": "/var/lib/ultramarine-apps/.config/containers/systemd",
  "files_base_dir": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets",
  "files": [
    {
      "filename": "app.container",
      "path": "/var/lib/ultramarine-apps/.config/containers/systemd/app.container",
      "quadlet": true
    },
    {
      "filename": "app/index.html",
      "path": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets/app/index.html",
      "quadlet": false
    }
  ]
}
```

To read a companion file from the companion-file directory, include
`"companion": true` in the `read` payload.

`delete` payload:

```json
{
  "scope": "apps",
  "filename": "app.container",
  "dry_run": true
}
```

### apps

Feature: `apps`

Cooks recipes into installed Quadlet-backed apps and manages their lifecycle.
An app is a named bundle: rendered Quadlet units land in the Quadlet scan
directory, while companion files and a manifest (`app.json`) live under a
per-app directory inside the companion-file data root (the same roots used by
the `quadlets` module).

Every action takes `scope`, an `AppScope`:

- `"apps"` (the default): a rootless app of the `ultramarine-apps` system
  account (UID/GID 242, home `/var/lib/ultramarine-apps`). Units go to its
  `~/.config/containers/systemd`, the bundle to its
  `~/.local/share/tetra/quadlets/<name>`, all owned by the account (see
  [quadlets](#quadlets)), and the services run in its lingering user manager
  (`systemctl --user -M ultramarine-apps@`).
- `"system"`: a rootful app, for real system services:
  `/etc/containers/systemd`, `/var/lib/tetra/quadlets/<name>` (root's) and
  the system manager.

The manifest records the scope, and `get`, `update` and `remove` refuse an
app whose manifest names another scope, so an app stays where it was
installed: apps that earlier releases installed in system scope keep working
with `"scope": "system"` (they are not listed in apps scope). Tetra does not
move them; reinstalling one in apps scope (and moving its data) is up to the
administrator. A `"user"` scope (earlier releases' per-user home) is refused,
and a manifest that says `user` is listed as `invalid`. The manifest records the recipe source, parameter
values, installed unit filenames, and companion files so `update` can
re-render and `remove` can clean up without the caller resending the recipe.

Request payloads deserialize into the `App*` types in `src/types/apps.rs`
(`AppCreateRequest`, `AppUpdateRequest`, `AppGetRequest`, `AppListRequest`,
`AppRequest` for `remove`), and the manifest is the serialized `AppManifest`
type. The recipe source is `AppRecipeSource`: exactly one of an inline recipe
(`recipe` plus optional `templates`) or an on-disk recipe (`recipe_path` plus
optional `templates_dir`).

Actions:

- `list`
- `get`
- `create` (privileged)
- `update` (privileged)
- `remove` (privileged)

`create`/`update` also accept `source: {catalog: "official"|"community"|"custom",
url?, sha256}` and `allow_unpinned_images`. Pinning is enabled by default; only
custom may explicitly opt out. Supplied source digests are always checked before
install writes. Missing source on create/replacement means custom. On update
without a replacement recipe, omitted source and opt-out retain the manifest
policy; replacement resets policy unless explicitly supplied. The manifest
records verified `source` (including computed digest) and `allow_unpinned_images`,
and disk recipes are stored as inline snapshots. Old manifests deserialize with
no source and pinning enabled. See [verification algorithm and image policy](recipes.md#install-time-source-verification-and-image-pinning).

App names may contain letters, digits, `.`, `_`, and `-`, and must not start
with `.` or `-`.

`create` payload (inline recipe):

```json
{
  "name": "my-site",
  "scope": "apps",
  "recipe": "id: nginx-site\n...",
  "templates": {
    "app.container": "[Container]\nImage=docker.io/library/nginx:alpine@sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417\n"
  },
  "values": {
    "app_id": "my-site"
  },
  "selinux": {
    "context_type": "container_unit_file_t",
    "recursive": true
  },
  "converge": false,
  "dry_run": true
}
```

A recipe can also be loaded from disk instead:

```json
{
  "name": "my-site",
  "recipe_path": "/srv/recipes/site.yaml",
  "templates_dir": "/srv/recipes/templates",
  "values_path": "/srv/recipes/values.yaml"
}
```

Inline `values` are merged over the optional `values_path` file, so recipe
defaults and per-instance overrides can ship in one call.

If the recipe declares a `bundle_dir` parameter and the caller does not
supply a value for it, `create` and `update` inject the app's bundle
directory path (e.g. `/var/lib/ultramarine-apps/.local/share/tetra/quadlets/my-site`)
so templates can
bind-mount companion files with `Volume={{ bundle_dir }}/...` without the
caller knowing the agent's layout. An explicitly supplied `bundle_dir`
always wins, and recipes that do not declare the parameter are unaffected
(undeclared values never reach the render context).

`create` renders the recipe, writes the Quadlet units and companion files,
writes `<bundle>/app.json`, optionally applies SELinux contexts to the bundle,
and — unless `converge` is `false` — prepares the apps account (apps scope),
runs `systemctl daemon-reload`, then starts the derived services. Quadlet services are generated units, which
`systemctl enable` refuses; a unit's `[Install]` section (for example
`WantedBy=default.target`) is what starts it at boot. Service names are derived from unit
filenames: `.container` and `.kube` units map to `<stem>.service`, `.pod`
units to `<stem>-pod.service`; network and volume units have no service.
`converge` defaults to `true`; `create` and `update` never run `systemctl
enable` or `disable`.

Preparing the apps account (`account` in the response; empty in system
scope or with `converge: false`) makes sure the host can run rootless apps,
skipping what is already there:

1. Subordinate UIDs and GIDs, which `systemd-sysusers` does not allocate:
   when `/etc/subuid` or `/etc/subgid` has no range for `ultramarine-apps`
   (by name or UID), `usermod --add-subuids FIRST-LAST --add-subgids
   FIRST-LAST ultramarine-apps` with the first free range of 65536 IDs from
   524288 up, as `useradd` picks them (Fedora's `SUB_UID_MIN`/`COUNT`).
2. Lingering: `loginctl enable-linger ultramarine-apps` unless
   `/var/lib/systemd/linger/ultramarine-apps` exists (the packaged
   `tetra.tmpfiles.conf` creates it), then `systemctl start user@242.service`,
   so the account's manager is running before Tetra talks to it.
3. On SELinux hosts, unless the policy's `file_contexts.subs` already has it:
   `semanage fcontext -a -e /var/lib/containers/storage
   /var/lib/ultramarine-apps/.local/share/containers/storage` and `restorecon
   -R` on it, so rootless storage gets the labels of rootful storage (a home
   under `/var/lib` gets none of the `HOME_DIR` rules that label rootless
   storage in `/home`).

The account must exist (`systemd-sysusers`); converging in apps scope fails
otherwise. Rootless containers cannot publish ports below 1024 unless the
host lowers `net.ipv4.ip_unprivileged_port_start`; put a reverse proxy in
front instead. Units must use `WantedBy=default.target` (as the shipped
recipes do): the user manager has no `multi-user.target`.

A parameter with a `generate` strategy (such as `random_32`) and neither a
value nor a default is generated once and stored in the manifest with the
other values, so later `update`s keep it instead of generating a new secret.
`app.json` is written atomically and private (`0600`, the apps account's in
apps scope, root's in system scope), because it holds those values. The `create` and `update` responses return the manifest as stored,
secrets included; only `get` redacts them.

Response:

```json
{
  "app": {
    "version": 1,
    "name": "my-site",
    "scope": "apps",
    "recipe_id": "nginx-site",
    "recipe_version": "0.1.0",
    "recipe": { "source": "inline", "recipe": "...", "templates": {} },
    "values": { "app_id": "my-site" },
    "units": ["my-site.container"],
    "files": ["index.html"],
    "created_at": 1750000000,
    "updated_at": 1750000000
  },
  "base_dir": "/var/lib/ultramarine-apps/.config/containers/systemd",
  "bundle_dir": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets/my-site",
  "owner": "ultramarine-apps",
  "manifest_path": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets/my-site/app.json",
  "units": ["my-site.container"],
  "files": ["index.html"],
  "services": ["my-site.service"],
  "account": [],
  "systemd": [],
  "selinux": [],
  "written": true,
  "dry_run": false
}
```

`list` payload:

```json
{ "scope": "apps" }
```

Returns one summary per app plus an `invalid` array naming bundle directories
whose manifest could not be read (corrupted bundles or stray unmanaged
directories):

```json
{
  "files_base_dir": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets",
  "apps": [
    {
      "name": "my-site",
      "recipe_id": "nginx-site",
      "recipe_version": "0.1.0",
      "scope": "apps",
      "units": ["my-site.container"],
      "services": ["my-site.service"],
      "created_at": 1750000000,
      "updated_at": 1750000000,
      "bundle_dir": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets/my-site"
    }
  ],
  "invalid": []
}
```

`get` payload:

```json
{ "name": "my-site", "scope": "apps" }
```

Returns the manifest plus the unit listing (each unit with its absolute path
and an `exists` flag), the companion files and the derived services. `get` is
open to users granted `apps: view`, so the values of the recipe's `secret`
parameters are replaced by `"********"` (every value is, if the stored recipe
cannot be read).

`update` payload:

```json
{
  "name": "my-site",
  "values": { "app_id": "my-site" },
  "dry_run": true
}
```

Loads the stored manifest, optionally replaces the recipe source (same fields
as `create`, for recipe upgrades), merges `values` per key over the stored
values so previously collected secrets do not need to be resent, re-renders,
installs the new bundle, deletes units and companion files that are no longer
rendered, rewrites the manifest, and (unless `converge` is `false`) runs
`daemon-reload` and restarts the derived services. The response adds
`removed_units` and `removed_files`.

A value of `"********"` for a secret parameter (for any parameter, if the
recipe cannot be read) is ignored and the stored value kept, so the values
from `get` can be sent back unchanged.

`remove` payload:

```json
{
  "name": "my-site",
  "scope": "apps",
  "converge": true,
  "dry_run": true
}
```

Stops the derived services (failures are reported inline in the
`systemd` array and tolerated), deletes the Quadlet units, runs
`daemon-reload`, and removes the bundle directory. Volumes created by Podman
for the app's `.volume` units are intentionally preserved.

`create`, `update`, and `remove` all honor `dry_run`, which previews the file
writes and the exact `usermod`, `loginctl`, `semanage` and `systemctl`
commands without changing the host. In apps scope these are
`systemctl --user -M ultramarine-apps@ daemon-reload` and
`systemctl --user -M ultramarine-apps@ start|restart|stop <service>`. Setting
`converge: false` skips systemd interaction entirely, which is useful for
staging files on hosts without systemd.

### services

Feature: `services`

Backed by `systemctl` and `journalctl`.

Actions:

- `list`
- `status`
- `logs`
- `daemon_reload` (privileged)
- `start` (privileged)
- `stop` (privileged)
- `restart` (privileged)
- `enable` (privileged)
- `disable` (privileged)

Every action takes an optional `scope`:

- `system` (the default): the system manager.
- `user`: the user manager of whoever the command runs as (`systemctl
  --user`, `journalctl --user`).
- `apps`: the user manager of `ultramarine-apps`, where apps-scope apps run.
  As root (privileged actions, `run_as: root`) that is `systemctl --user -M
  ultramarine-apps@`, and `logs` reads `journalctl _UID=<uid>
  _SYSTEMD_USER_UNIT=<service>`; reads with `"run_as": "apps"` use plain
  `--user` as the account itself. A signed-in user's own `runuser` cannot
  reach the account's manager, so reads in this scope need `run_as`.

`list` payload:

```json
{ "scope": "apps", "run_as": "apps" }
```

Response payload includes raw command output and parsed `services`:

```json
{
  "services": [
    {
      "unit": "sshd.service",
      "load": "loaded",
      "active": "active",
      "sub": "running",
      "description": "OpenSSH server daemon"
    }
  ]
}
```

`status` payload:

```json
{ "service": "sshd.service" }
```

`logs` payload:

```json
{ "service": "sshd.service", "lines": 100 }
```

`lines` defaults to 100.

Mutation payload (`start`, `stop`, `restart`, `enable`, `disable` run
`systemctl <action> <service>`):

```json
{ "service": "sshd.service", "dry_run": true }
```

`daemon_reload` runs `systemctl daemon-reload`, for example after writing
Quadlet files with the `quadlets` module:

```json
{ "scope": "system", "dry_run": true }
```

### selinux

Feature: `selinux`

Backed by `sestatus`, `getenforce`, `getsebool`, `setsebool`, `semanage`, and
`restorecon`.

Actions:

- `status`
- `enforce` (privileged)
- `booleans`
- `set_boolean` (privileged)
- `file_contexts`
- `add_file_context` (privileged)
- `delete_file_context` (privileged)
- `restore_context` (privileged)

`status` payload:

```json
{}
```

Response payload includes parsed `selinux` status fields.

`booleans` payload:

```json
{}
```

Response payload:

```json
{
  "booleans": [
    {
      "name": "virt_use_nfs",
      "enabled": false,
      "value": "off"
    }
  ]
}
```

`set_boolean` payload:

```json
{
  "name": "virt_use_nfs",
  "value": true,
  "persistent": true,
  "dry_run": true
}
```

`add_file_context` payload:

```json
{
  "path_pattern": "/srv/media(/.*)?",
  "context_type": "samba_share_t",
  "dry_run": true
}
```

`delete_file_context` payload:

```json
{
  "path_pattern": "/srv/media(/.*)?",
  "dry_run": true
}
```

`restore_context` payload:

```json
{
  "path": "/srv/media",
  "recursive": true,
  "dry_run": true
}
```

### storage

Feature: `storage`

Actions:

- `list`
- `status`
- `zfs`
- `mount` (privileged)
- `unmount` (privileged)
- `configure` (privileged)

`list` returns parsed `/proc/mounts` and `/proc/partitions` data.

`zfs` is a read-only discovery action. It reports whether the ZFS kernel
module or command-line tools are present and, when available, returns `pools`
and `datasets` from `zpool list` and `zfs list`. Missing ZFS support returns
`available: false` with empty arrays rather than an error.

`status` also includes the same `zfs` discovery object.

`status` payload:

```json
{ "path": "/srv/data" }
```

`mount` payload:

```json
{
  "source": "/dev/disk/by-label/data",
  "target": "/srv/data",
  "fstype": "xfs",
  "options": "defaults",
  "dry_run": true,
  "selinux": {
    "context_type": "container_file_t",
    "recursive": true
  }
}
```

`mount` response payload contains:

```json
{
  "mount": { "command": "mount ..." },
  "selinux": []
}
```

`unmount` payload:

```json
{ "path": "/srv/data", "dry_run": true }
```

`configure` payload:

```json
{
  "fstab_path": "/etc/fstab",
  "entry": "/dev/disk/by-label/data /srv/data xfs defaults 0 0",
  "dry_run": true
}
```

`configure` appends `entry` to `fstab_path` (default `/etc/fstab`). The entry
must be one line of 2 to 6 fields and not a comment. The response has
`fstab_path`, `configured`, `dry_run` and `selinux`.

`status` runs `df -h PATH` and returns `{result, dry_run, zfs}`. `mount` runs
`mount [-t fstype] [-o options] source target`.

### samba

Feature: `samba`

Actions:

- `list_shares`
- `get_config`
- `set_config` (privileged)
- `reload` (privileged)
- `enable` (privileged)
- `disable` (privileged)

Default config path: `/etc/samba/smb.conf`

`list_shares` and `get_config` payload:

```json
{ "path": "/etc/samba/smb.conf" }
```

`set_config` payload:

```json
{
  "path": "/etc/samba/smb.conf",
  "contents": "[media]\npath = /srv/media\nread only = no\n",
  "dry_run": true,
  "selinux": {
    "path": "/srv/media",
    "context_type": "samba_share_t",
    "recursive": true
  }
}
```

Service actions accept:

```json
{ "dry_run": true }
```

`list_shares` returns `{path, shares}`, `get_config` `{path, contents}`.
`set_config` replaces the whole file (send the complete `smb.conf`, including
`[global]`) in place, keeping its owner, mode and label; the shared `selinux`
object defaults its `path` to the config file, so pass the share directory to
label it. As with `files`, the config must be a regular file, and reads are
limited to 16 MiB. `reload` runs `systemctl reload-or-restart smb.service`;
`enable` and `disable` run `systemctl enable --now`/`disable --now` on it.

`set_config` is administrator-only on the local socket (an `smb.conf` can run
commands as root), and users granted `sharing` may only use the default
`path`.

### nfs

Feature: `nfs`

Actions:

- `list_exports`
- `get_config`
- `set_config` (privileged)
- `reload` (privileged)
- `enable` (privileged)
- `disable` (privileged)

Default config path: `/etc/exports`

`list_exports` and `get_config` payload:

```json
{ "path": "/etc/exports" }
```

`set_config` payload:

```json
{
  "path": "/etc/exports",
  "contents": "/srv/export *(rw,sync,no_subtree_check)\n",
  "dry_run": true,
  "selinux": {
    "path": "/srv/export",
    "context_type": "public_content_rw_t",
    "recursive": true
  }
}
```

Service actions accept:

```json
{ "dry_run": true }
```

`list_exports` returns `{path, exports}`, `get_config` `{path, contents}`.
`set_config` replaces the whole file in place, like `samba.set_config`.
`reload` runs `exportfs -ra`; `enable` and `disable` run `systemctl enable
--now`/`disable --now` on `nfs-server.service`.

`set_config` is administrator-only on the local socket (an export with
`no_root_squash` is root-equivalent), and users granted `sharing` may only
use the default `path`.

### network

Feature: `network`

Actions:

- `interfaces`
- `status`
- `dns`
- `routes`
- `configure` (privileged)
- `confirm` (privileged)
- `pending` (privileged)
- `get_config` (privileged)
- `set_config` (privileged)
- `reload` (privileged)
- `scan_wifi` (privileged)
- `connect_wifi` (privileged)

`interfaces` returns interface names, types, MAC addresses, and operstate
from `/sys/class/net`, plus each interface's IPv4 and IPv6 `addresses`:

```json
{
  "name": "eth0",
  "type": "ethernet",
  "operstate": "up",
  "mac": "52:54:00:12:34:56",
  "addresses": [
    { "interface": "eth0", "family": "ipv6", "address": "2001:db8::2", "prefix_length": 64, "scope": "global" },
    { "interface": "eth0", "family": "ipv6", "address": "fe80::5054:ff:fe12:3456", "prefix_length": 64, "scope": "link-local" }
  ]
}
```

`type` is read from the interface's sysfs directory:

- `wifi`: a wireless device (`DEVTYPE=wlan` in `uevent`, or a `wireless` or
  `phy80211` entry). Only these can be used with `scan_wifi` and
  `connect_wifi`.
- `ethernet`: a physical Ethernet device: link `type` is `1` (`ARPHRD_ETHER`),
  it has a `device` link, and its `uevent` has no `DEVTYPE` (so it is not
  wireless, a WWAN modem, a VLAN, a bridge, a bond, ...). Only these can be
  used with `configure`.
- `other`: everything else, such as loopback, bridges, bonds, VLANs, veth
  pairs, WWAN modems, Podman networks, Tailscale and other tun devices, and
  other virtual interfaces.

`scope` is derived from the address prefix, not the kernel's scope field:
`global`, `private` (RFC 1918 and RFC 6598 IPv4), `ula` (`fc00::/7`),
`link-local`, `loopback`, `multicast` or `unspecified`. `global`, `private`
and `ula` count as routable.

`dns` returns the current `/etc/resolv.conf` contents in `resolv_conf` (or
`null` when unavailable). `routes` returns parsed JSON output from
`ip -json route show`. Both actions are read-only.

`status` payload:

```json
{ "interface": "enp1s0" }
```

Response includes raw `ip -json addr show` output parsed into `data`, and the
same classified `addresses` list as `interfaces`.

`configure` writes a NetworkManager keyfile for one Ethernet interface from
structured settings. Tetra validates the payload, writes
`/etc/NetworkManager/system-connections/<name>.nmconnection` with mode `0600`
and its default SELinux label, then loads and activates it.

```json
{
  "interface": "eth0",
  "name": "eth0",
  "ipv4": { "method": "disabled" },
  "ipv6": {
    "method": "manual",
    "addresses": [{ "address": "2001:db8:10::2", "prefix_length": 64 }],
    "gateway": "fe80::1",
    "dns": ["2606:4700:4700::1111"]
  },
  "dry_run": false
}
```

- `name` is the profile name and keyfile stem; it defaults to `interface`.
  Rewriting an existing profile keeps its UUID.
- `ipv4.method`: `auto` (DHCP, the default), `manual` or `disabled`.
- `ipv6.method`: `auto` (SLAAC, plus DHCPv6 as NetworkManager decides; the
  default), `dhcp`, `manual`, `link-local` or `disabled`.
- `addresses` (required with `manual`, rejected otherwise) take a
  `prefix_length` of 1–32 for IPv4 and 1–128 for IPv6. `gateway` is optional
  and only allowed with `manual`; an IPv6 gateway may be link-local. `dns` is
  allowed unless the family is `disabled` or `link-local`. Every address must
  match its section's family.
- At least one family must give the host a routable address, so both families
  `disabled` (or IPv4 `disabled` with IPv6 `link-local`) is rejected.
- `wired_8021x` (optional) adds wired 802.1X as the keyfile's `[802-1x]`
  section: `{eap, identity, anonymous_identity?, password?, ca_cert?,
  client_cert?, private_key?, private_key_password?, domain_suffix_match?,
  phase2?}`. `eap` is `tls`, `peap`, `ttls`, `pwd` or `md5`; `tls` needs
  `client_cert` and `private_key` and takes no `password`, the others need
  `password`. `phase2` and `anonymous_identity` are for `peap` and `ttls`:
  `phase2` is `mschapv2` (the default), `gtc` or `md5` for `peap`, and any of
  those or `mschap`, `pap` or `chap` for `ttls`. A `tls` key without
  `private_key_password` is taken to be unencrypted
  (`private-key-password-flags=4`, so NetworkManager does not ask for one).
- `ca_cert`, `client_cert` and `private_key` are each an absolute path or
  PEM contents (up to 64 KiB, starting with `-----BEGIN `). NetworkManager
  reads these files as root, so a path must name a regular file under
  `/etc/pki/` once symlinks are resolved (not, say, a private key of
  another service elsewhere, or a FIFO or device); the keyfile names the
  resolved path, so it always refers to the file that was checked. Tetra stores PEM
  contents under `/etc/pki/tetra/802-1x/<profile>/` (directories `0700`,
  files `0600`, root only, default SELinux label), named by a hash of the
  contents, and writes those paths into the keyfile. Once a change settles
  (applied, confirmed or rolled back), files the profile on disk no longer
  names are deleted, and the directory with the last one (if the profile
  cannot be read, nothing is deleted). So a path under
  `/etc/pki/tetra/802-1x/` is only accepted inside the profile's own
  directory (`<name>` for `configure`, `wifi-<interface>` for
  `connect_wifi`): another profile's files may be deleted when that
  profile changes. A change that is rolled back, and a `connect_wifi`
  profile that never came up, take their new files with them. A
  `configure` profile that fails to activate is not undone right away: it
  goes through safe apply (below) like any other change, so it is rolled
  back, with its new files, unless it is confirmed, the interface had no
  routable address before, or one of those addresses is still there (the
  previous profile stayed up, say).
- `ca_cert` is what authenticates the network's authentication server.
  Without it (and without `domain_suffix_match`), `tls`, `peap` and `ttls`
  accept any server certificate, so a rogue access point or switch port can
  pose as the network and, for `peap` and `ttls`, collect the inner
  credentials.
- `domain_suffix_match` (`tls`, `peap` and `ttls` only) is a domain name;
  the authentication server's certificate must name it or a subdomain
  (`802-1x.domain-suffix-match`). Without `ca_cert`, that certificate is
  checked against the system CAs (`system-ca-certs=true`).
- The keyfile in `configure` and `connect_wifi` responses has passwords
  replaced by `<redacted>`. Passwords, `private_key_password` and key
  contents never appear on a command line, in those responses, in an error
  or in the action log. `get_config` (admin only) returns keyfiles as
  stored, passwords included.
- Unknown fields are rejected.

With `dry_run`, the response holds the `path`, `uuid` and rendered `keyfile`
and nothing is written. Otherwise the response also reports `applied`,
`activation_error` (or `null`), `addresses_before`, `addresses_after`,
`gateways_before` and `gateways_after`.

Safe apply: before writing anything, Tetra records the interface's routable
addresses and the gateways of its default routes, and creates a
NetworkManager checkpoint of the interface's device (`CheckpointCreate` over
D-Bus, with `DELETE_NEW_CONNECTIONS`). If none of those addresses is present
again shortly after activation, or the interface had default routes and none
of their gateways is, the change needs confirmation. If the profile also
failed to activate, it is undone at once (through the checkpoint) and the
action fails. Otherwise the response has `"confirmation_required": true`, a
`confirmation_token`, `rollback_in_seconds` (60), `rollback_by`
(`networkmanager`, or `tetra` without a checkpoint) and `checkpoint` (its
D-Bus path, or `null`). A change that keeps the host reachable destroys its
checkpoint right away and needs no confirmation.

Unless the caller sends `confirm` within that time, NetworkManager itself
rolls the device back to the checkpoint: it restores the previously active
profile (on disk too) and reactivates it, and deletes a profile the change
added. This happens inside NetworkManager, so it does not depend on Tetra:
a Tetra crash or restart inside the window, or one in the middle of
applying, still gets the old network back. A few seconds later Tetra
finishes the rollback: it puts the previous keyfile back byte for byte
(also for a changed profile that was not the active one, which the
checkpoint does not cover), removes a new keyfile NetworkManager did not, and
reactivates the previous profile if NetworkManager did not.

The pending change, previous keyfile included, is recorded in
`/var/lib/tetra/network/pending.json` (directory `0700`, file `0600`, root
only) until it settles, so `pending` and `confirm` keep working after a Tetra
restart. Tetra picks the record up on its first network action after
starting. If the rollback is overdue by then (Tetra was down past the
deadline), or NetworkManager restarted and dropped the checkpoint without
rolling back (it keeps checkpoints in memory only), Tetra rolls the change
back itself at the deadline, including after a reboot. If NetworkManager
cannot create a checkpoint (no D-Bus, a NetworkManager older than 1.6, or
another tool's checkpoint already covering the device), Tetra logs a
warning and rolls back by itself from the same record (`rollback_by:
"tetra"`); then a Tetra restart inside the window delays the rollback until
Tetra is back. Only one change can await confirmation at a time.

The checkpoint covers only the configured interface's device, but
`DELETE_NEW_CONNECTIONS` makes its rollback delete every profile added
anywhere while the change was pending (including in-memory profiles
NetworkManager generates for devices that appeared meanwhile, such as a new
container's veth).

`confirm` payload:

```json
{ "token": "..." }
```

The change usually cuts the connection its response was sent on, so
`pending` (no payload) returns the change awaiting confirmation, if any:
`{"pending": {"confirmation_token", "interface", "path",
"rollback_in_seconds", "rollback_by", "checkpoint"}}` or
`{"pending": null}`. `confirm` destroys the checkpoint; it fails if the
change was already rolled back, or if NetworkManager is unreachable (the
change then stays pending and still rolls back). `set_config` refuses the
keyfile of a pending change. When a change needs confirmation, the outbound
control-plane session drops and redials at once instead of waiting out its
idle timeout, so a controller should call `pending` and `confirm` after it
reconnects.

`scan_wifi` lists the networks a wireless interface can see, from
`nmcli device wifi list`:

```json
{ "interface": "wlan0", "rescan": true }
```

`rescan: true` always scans first and `false` never does; by default
NetworkManager scans when its last scan is more than 30 seconds old. The
response is `{"networks": [...]}`, strongest first, one entry per SSID:

```json
{ "ssid": "Home", "security": "wpa-personal", "signal": 82, "frequency": 5180, "in_use": true }
```

`security` is `open`, `wpa-personal` (WPA2 or WPA3), `wpa-enterprise`
(802.1X) or `unknown` (WEP, OWE, WPA3-Enterprise 192-bit and others
`connect_wifi` cannot join).
Hidden networks are not listed.

`connect_wifi` writes `/etc/NetworkManager/system-connections/wifi-<interface>.nmconnection`
(mode `0600`, default SELinux label) and activates it. Each interface has
one Wi-Fi profile, so connecting to another network replaces it and keeps
its UUID.

```json
{
  "interface": "wlan0",
  "ssid": "Home",
  "hidden": false,
  "security": { "type": "wpa-personal", "password": "..." },
  "dry_run": false
}
```

- `security.type` is `open`, `wpa-personal` with `password`, or
  `wpa-enterprise` with the same fields as `wired_8021x` above, except that
  `eap` cannot be `md5` (it derives no keys to encrypt Wi-Fi with).
- Key management is decided when connecting, from the scan: for networks
  the scan shows as WPA3-only, Tetra uses SAE (`key-mgmt=sae`), whose
  passwords are 1–128 characters; otherwise WPA-PSK (`key-mgmt=wpa-psk`),
  whose passwords are 8–63 printable ASCII characters or 64 hex digits.
- A network the last scan did not see is written with `hidden=true`, as is
  any network sent with `hidden: true`. If the scan itself fails (the
  interface is not a Wi-Fi device, or its radio is off, say),
  `connect_wifi` fails with that error and writes nothing.
- IPv4 and IPv6 use `auto`.
- Unknown fields are rejected.

The password goes only into the keyfile: it is never on a command line, and
the `keyfile` in responses shows `<redacted>`. `connect_wifi` uses the same
safe apply as `configure` (including `confirmation_required` when the
interface lost every address it had). If the profile does not come up (a
wrong password, say), Tetra restores the previous profile, or removes the
new one, and returns an error. With `dry_run`, nothing is scanned or
written, so the preview shows `key-mgmt=wpa-psk` and `hidden` only as sent,
the password is only checked against SAE's rules, and the response's `note`
says so.

`get_config` and `set_config` give raw access to keyfiles, restricted to
regular `.nmconnection` files directly inside
`/etc/NetworkManager/system-connections/`. Paths that are relative, contain
`..`, point elsewhere, or name a symlink or other non-regular file are
rejected. `set_config` replaces the file atomically with mode `0600` and
relabels it with `restorecon`.

`get_config` payload:

```json
{ "path": "/etc/NetworkManager/system-connections/example.nmconnection" }
```

`set_config` payload:

```json
{
  "path": "/etc/NetworkManager/system-connections/example.nmconnection",
  "contents": "[connection]\nid=example\n",
  "dry_run": true
}
```

`reload` payload:

```json
{ "dry_run": true }
```

### reverse_proxy

Feature: `reverse-proxy`

Manages Caddy sites for hosted services, one `*.caddyfile` per domain in
`/etc/caddy/Caddyfile.d`, which terra-caddy's default Caddyfile imports. The
file name is the domain with `.` replaced by `_` (`app.example.com` →
`app_example_com.caddyfile`).

Actions:

- `list`
- `render`
- `write` (privileged)
- `delete` (privileged)
- `reload` (privileged)

Every action except `reload` accepts `config_dir` to use another directory.
Only administrators and remote controllers may set it; everyone else gets the
default.

`list` takes `{}` and returns `{config_dir, sites}`, sorted by domain. A site
is `{filename, path, domain, upstream, tls}`. Only files Tetra wrote are
listed: ones whose first line is `# Managed by Tetra reverse_proxy` and that
carry a readable `# tetra:` metadata line. The dashboard's and the OOBE's own
sites are not listed.

`render` and `write` payload:

```json
{
  "domain": "app.example.com",
  "upstream": "127.0.0.1:8080",
  "tls": true,
  "reload": true,
  "dry_run": false
}
```

`write` creates or replaces the site:

```caddyfile
# Managed by Tetra reverse_proxy
# tetra: {"domain":"app.example.com","upstream":"127.0.0.1:8080","tls":true}
app.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

- `domain` is trimmed, lowercased and stripped of a trailing dot, then must
  be a DNS name: dot-separated labels of 1–63 letters, digits and inner
  hyphens, at most 253 characters. Wildcards are not accepted.
- `upstream` is trimmed and must be one address made only of letters,
  digits, `.`, `-`, `_`, `:`, `[`, `]` and `/`, containing a `:` (host and
  port), such as `127.0.0.1:8080` or `[::1]:8080`. Whitespace, braces and
  newlines are refused, so a payload cannot add upstreams or directives to
  the site.
- `tls` defaults to `true` (Caddy's automatic HTTPS). `false` writes an
  `http://domain` site address, served over plain HTTP without a
  certificate.
- The file is written atomically with mode `0644` (Caddy reads it as
  `caddy`), creating `config_dir` if needed.
- `write` and `delete` refuse an existing file that does not start with the
  managed header (an operator's own site), and domains whose file name would
  be one of Tetra's own sites (`00-ultramarine-dashboard.caddyfile`,
  `00-ultramarine-setup.caddyfile`).
- With `reload: true` (default `false`), Caddy is reloaded after the change
  (`systemctl reload caddy.service`). A failed reload does not fail the
  action, since the file already changed: its error is returned in
  `reload_error`.

`render` previews the site without writing: `{config_dir, filename, contents,
site, dry_run, reload}`. `write` returns `{config_dir, filename, path,
contents, site, written, dry_run, reload, reload_error}`, where `reload` is
the reload's command result or `null`.

`delete` payload:

```json
{ "domain": "app.example.com", "reload": true, "dry_run": false }
```

It removes the site (a missing file is not an error) and returns
`{config_dir, filename, path, deleted, dry_run, reload, reload_error}`.

`reload` takes `{ "dry_run": false }` and runs `systemctl reload
caddy.service`.

`list` and `render` need `network: view`; `write`, `delete` and `reload` need
`network: manage`.

Sites written by released versions up to 0.2.3 to
`/etc/caddy/tetra-sites/<domain>.caddy` are moved here when `tetra
agent-serve` starts (see "Caddy" in [auth-protocol.md](auth-protocol.md#caddy)).

### podman

Feature: `podman`

Actions:

- `containers`
- `inspect`
- `images`
- `volumes`
- `networks`
- `logs`
- `start` (privileged)
- `stop` (privileged)
- `restart` (privileged)
- `remove` (privileged)

Reads run as `ultramarine-apps` by default, so they show the containers,
images, volumes and networks of user apps; send `"run_as": "root"`
(administrators) for rootful ones, or `"run_as": "user"` for the signed-in
user's own (see [Run As](#run-as)). Mutations always run as root, so they
act on rootful containers; manage apps through `apps` and `services` with
`"scope": "apps"` instead.

List actions return raw command output plus parsed JSON in `data`.

`inspect` returns `podman inspect NAME` output in `data`. Environment values
are replaced by `********` (`Config.Env` and the `--env`/`-e` arguments in
`Config.CreateCommand`, in `data` and `stdout`), since apps keep secrets
there (`Environment=DB_PASSWORD=...`) and the Containers page may be granted
to non-administrators. `"show_env": true` returns them unredacted and is
administrator-only.

`inspect` payload:

```json
{ "name": "app", "show_env": false }
```

`logs` payload:

```json
{ "name": "app", "lines": 100 }
```

`lines` defaults to 100. `logs` returns the command result without parsing.

Mutation payload (`start`, `stop`, `restart`, and `remove`, which runs
`podman rm` without `--force`):

```json
{ "name": "app", "dry_run": true }
```

### users

Feature: `users`

Actions:

- `list`
- `groups`
- `status`
- `create` (privileged)
- `update` (privileged)
- `delete` (privileged)
- `set_password` (privileged)
- `set_authorized_keys` (privileged)
- `add_admin` (privileged)

Every action except `list`, `groups` and `status` is privileged.

Account names (`name`) and the `groups` of `update` must be 1–32
characters from `A-Z a-z 0-9 _ . -`, not start with `-` or `.`, not be all
digits, and may end in `$`. Anything else is refused before a command runs,
so a name can never be read as an option.

`list` parses `/etc/passwd`; `groups` parses `/etc/group`.

`status` and `delete` payload:

```json
{ "name": "alice", "dry_run": true }
```

`create` payload:

```json
{
  "name": "alice",
  "shell": "/bin/bash",
  "home": "/home/alice",
  "system": false,
  "dry_run": true
}
```

`update` payload:

```json
{
  "name": "alice",
  "shell": "/bin/bash",
  "home": "/home/alice",
  "groups": ["wheel", "podman"],
  "dry_run": true
}
```

`set_password` payload:

```json
{
  "name": "alice",
  "password_hash": "$y$j9T$...",
  "dry_run": true
}
```

`password_hash` is a `crypt(3)` hash as `/etc/shadow` stores it: printable
ASCII without spaces or `:`. Tetra feeds `name:password_hash` to
`chpasswd --encrypted` on stdin, so the hash is never on a command line, and
the response's `command` (also in errors and the action log) shows
`chpasswd --encrypted <<< 'alice:<password hash>'` instead of it.

`set_authorized_keys` replaces `~/.ssh/authorized_keys` for an existing
account:

```json
{
  "name": "alice",
  "keys": ["ssh-ed25519 AAAAC3Nza... alice@laptop"],
  "dry_run": true
}
```

- Up to 100 keys, each one line of at most 16 KiB without control
  characters, with an OpenSSH key type (`ssh-…`, `ecdsa-sha2-…`, `sk-ssh-…`,
  `sk-ecdsa-sha2-…`). An empty list empties the file.
- `.ssh` is `0700` and the file `0600`, both owned by the user. Tetra writes
  through directory handles without following symlinks, so a symlinked
  `.ssh` or `authorized_keys` cannot redirect the write. On SELinux hosts it
  then runs `restorecon -R` on `.ssh`.
- The response has `name`, `path`, the number of `keys`, `written` and the
  `selinux` command results.

`add_admin` adds an existing account to the `ultramarine-admin` group
(`usermod --append --groups`), which makes it a dashboard administrator:

```json
{ "name": "alice", "dry_run": true }
```

The group must exist on the host. A setup session may only call `add_admin`
while no eligible administrator exists (see `docs/auth-protocol.md`).
A setup session may only call `set_password`, `set_authorized_keys` and
`add_admin` on accounts it created with `create`, never on `root`, and may
not set `home`.

### virtual_machines

Feature: `virtual-machines`

Backed by `virsh` and `journalctl`.

Actions:

- `list`
- `status`
- `logs`
- `start` (privileged)
- `stop` (privileged)
- `restart` (privileged)
- `create` (privileged)
- `delete` (privileged)

`list` returns parsed `domains`.

`status` payload:

```json
{ "name": "vm1" }
```

Response includes parsed `domain` info.

`logs` payload:

```json
{ "lines": 100 }
```

Mutation payloads:

```json
{ "name": "vm1", "dry_run": true }
```

`create` payload:

```json
{ "xml_path": "/var/lib/libvirt/images/vm1.xml", "dry_run": true }
```

`logs` returns the `libvirtd.service` journal (`lines` defaults to 100).
`start` runs `virsh start`, `stop` a graceful `virsh shutdown`, `restart`
`virsh reboot`, `create` registers a persistent domain with `virsh define`,
and `delete` runs `virsh undefine`, which keeps the disk images.

### power

Feature: `power`

Actions:

- `reboot` (privileged)
- `poweroff` (privileged)

Both take `{ "dry_run": false }` and answer before the host goes down: Tetra
starts a transient timer (`systemd-run --on-active=3 --unit=tetra-power-<action>
systemctl <action>`) and returns `{ "action", "in_seconds": 3, "dry_run",
"command" }`.

### updates

Feature: `updates`

Actions:

- `get_policy`
- `set_policy` (privileged)

The policy is `automatic` (a timer installs updates) or `notify`
(the timer is off; nothing is downloaded or installed until an administrator
does it, and nothing sends a notification either; the name is historical).
Tetra picks the timer for the install variant: on bootc hosts
(`/run/ostree-booted` exists) `bootc-fetch-apply-updates.timer`, which
stages the new image and reboots into it; otherwise `dnf5-automatic.timer`
from `dnf5-plugin-automatic`. `dnf5 automatic` only downloads by default
(`apply_updates = no`), so on those hosts `automatic` also installs
`/etc/systemd/system/dnf5-automatic.service.d/50-tetra.conf`, which runs it
with `--installupdates` (overriding `apply_updates`; the rest of
`/etc/dnf/automatic.conf`, such as `reboot`, still applies), and `notify`
removes it.

`set_policy` payload:

```json
{ "policy": "automatic", "dry_run": true }
```

It runs `systemctl enable --now` (`automatic`) or `disable --now`
(`notify`) on the timer, installing or removing the drop-in (with a
`systemctl daemon-reload` when it changes) on package-based hosts, and only
then stores the policy in `updates.json` in Tetra's state directory
(`/var/lib/tetra/updates.json`, versioned like the auth files). A failing
`disable` (for instance when `dnf5-plugin-automatic` is not installed, so
the timer does not exist) is listed in `commands` with its `error` and is
not fatal as long as `systemctl is-enabled` does not report the timer
`enabled` afterwards; a failing `enable` is. Rewriting the file keeps fields
a newer release added, and a file only a newer release may read is an error
before anything changes (dry runs included). The response has `policy`,
`variant` (`bootc` or `mutable`), `timer`, `stored`, `dry_run` and the
`commands` run (or planned).

`get_policy` takes `{}` (or `null`) and returns:

```json
{
  "policy": "automatic",
  "variant": "mutable",
  "timer": "dnf5-automatic.timer",
  "timer_enabled": true,
  "effective": "automatic",
  "mismatch": false
}
```

- `policy` is the stored policy, `null` until one is set.
- `timer_enabled` is whether `systemctl is-enabled` reports the timer
  `enabled`.
- `effective` is what the host does: `automatic` when the timer is enabled
  (on package-based hosts, with Tetra's drop-in), `notify` when it is not,
  and `null` when `dnf5-automatic.timer` is enabled without the drop-in
  (it then installs only if `/etc/dnf/automatic.conf` says so).
- `mismatch` is `true` when a stored `policy` differs from `effective`, for
  instance after the timer was changed outside Tetra; `set_policy` again
  brings the host back in line.

### remote_access

Feature: `remote-access`

Actions (all privileged):

- `status`
- `tailscale_up`
- `tailscale_disable`
- `cloudflared_set_token`
- `cloudflared_disable`

`tailscaled.service` and `cloudflared.service` ship disabled; these actions
turn them on and off. Credentials never appear on a command line, in a unit
file, in a response or in the action log; the tunnel token is sealed with
`systemd-creds` under `/var/lib/tetra/secrets/`, the Tailscale auth key is
not kept at all. Payload credentials are refused unless they are 1–4096
printable ASCII characters without spaces. Responses list
the `commands` run (or, with `dry_run`, planned).

`tailscale_up` payload:

```json
{ "auth_key": "tskey-auth-...", "serve": true, "funnel": false, "dry_run": false }
```

- The key is written to a new file of this call's own in `/run/tetra`
  (`tailscale-auth-key-<pid>-<random>`, created exclusively, mode `0600`)
  for `tailscale up --auth-key=file:<path>` and deleted right after. Tetra
  keeps no copy; tailscaled keeps its own node key.
- Tetra installs `tailscaled.service.d/50-tetra.conf`
  (`TS_PERMIT_CERT_UID=caddy`) so Caddy can get the node's `*.ts.net`
  certificate, and restarts tailscaled the first time it does so.
- After `tailscale serve reset`, `serve` (the default) forwards Caddy's HTTPS
  port as raw TCP on the tailnet (`tailscale serve --bg --tcp=<port>
  tcp://127.0.0.1:<port>`); `funnel: true` does the same on the internet with
  `tailscale funnel`, only on ports 443, 8443 and 10000. The port is the
  access port (443 by default). With neither, nothing is forwarded.
- `tailscale up` (`--timeout=60s`) and the forwarding command (run under
  `timeout 60s`) fail after 60 seconds instead of waiting forever, for
  instance without internet access or while Serve or Funnel is not enabled
  in the tailnet's policy; the failure is then undone like any other.
- The response has `enabled`, `serve`, `funnel`, `target`, `dry_run` and the
  node's `hostname` (its `*.ts.net` name), which `access.set` should use so
  the dashboard works over Tailscale.
- If a step fails, the error is returned after undoing what the call set
  up: the drop-in if it installed it, and tailscaled (`systemctl disable
  --now`) unless it was enabled or running before. When only the forwarding
  step failed the node stays logged in to the tailnet.
- The port is read from `access.json` in Tetra's state directory when
  `tailscale_up` runs, dry runs included; an unreadable file is an error, not
  port 443. While the drop-in is installed, `access.set` refuses to change
  the port (`conflict`): run `tailscale_disable`, change the port, then
  `tailscale_up` again.
- Tailscale forwards raw TCP without the PROXY protocol, so Caddy, the
  dashboard, `PAM_RHOST`, the logs and every per-address limit see all
  tailnet and Funnel clients as `127.0.0.1` (see "Clients forwarded by
  Tailscale" in `docs/auth-protocol.md`).

`tailscale_disable` takes `{ "dry_run": false }`: it resets serve, runs
`systemctl disable --now tailscaled.service` and removes the drop-in. A
failing `disable` (for instance
without tailscaled installed) is listed in `commands` with its `error` and
does not stop the cleanup; `enabled` then reports whether the unit is still
enabled.

`cloudflared_set_token` payload:

```json
{ "token": "eyJ...", "dry_run": false }
```

It seals the token and installs `cloudflared.service.d/50-tetra.conf`, which
loads it with `LoadCredentialEncrypted=`, points `TUNNEL_TOKEN_FILE` at it and
runs `cloudflared --no-autoupdate tunnel run`, then reloads systemd and
enables and restarts `cloudflared.service`. `cloudflared_disable` stops and
disables it and removes the drop-in and the sealed token; as with
`tailscale_disable`, a failing `disable` is reported, not fatal.

`status` takes `{}` (or `null`) and returns:

```json
{
  "tailscale": { "enabled": true, "serve": true, "funnel": false, "hostname": "server.tail1234.ts.net" },
  "cloudflared": { "enabled": false }
}
```

`hostname` is only present while tailscaled is running.

## Controller Guidance

1. Start with `agent.capabilities` and hide unsupported modules/actions.
2. Default destructive UI controls to `dry_run: true` for preview, then issue
   the same command with `dry_run: false` or omitted after confirmation.
3. Treat `payload.command` as diagnostic output, not as a stable API identity.
4. Prefer parsed fields such as `services`, `data`, `booleans`, and `domains`
   when present.
5. For Fedora hosts, surface SELinux configuration near path-based workflows:
   Samba shares, NFS exports, Podman/Quadlet storage, network config files, and
   generic file writes.
6. Preserve and display `error` strings from failed responses; module errors
   include command failures and payload validation failures.

## Minimal Controller Flow

```json
{
  "id": "1",
  "module": "agent",
  "action": "capabilities",
  "payload": {}
}
```

```json
{
  "id": "2",
  "module": "recipes",
  "action": "render",
  "payload": {
    "recipe_path": "schema.yaml",
    "templates_dir": "./templates",
    "values_path": "examples/nextcloud.values.yaml",
    "dry_run": true
  }
}
```

```json
{
  "id": "3",
  "module": "quadlets",
  "action": "install",
  "payload": {
    "scope": "apps",
    "dry_run": true,
    "resources": [
      {
        "filename": "nextcloud-app.container",
        "contents": "[Container]\nImage=nextcloud:latest\n"
      }
    ]
  }
}
```

```json
{
  "id": "4",
  "module": "services",
  "action": "restart",
  "payload": {
    "service": "nextcloud-app.service",
    "scope": "apps",
    "dry_run": true
  }
}
```
