# Tetra Agent Protocol

This document describes the JSON protocol used between an outside
dashboard/controller and the Tetra host agent.

The local CLI command `tetra agent-dispatch` accepts the same command envelope
that the transports carry.

For host-to-guest virtio-vsock smoke testing, `tetra agent-vsock-serve` runs a
Linux-only guest listener that accepts one raw `AgentCommand` JSON object per
connection and replies with one raw `AgentResponse` JSON object. This is a
development harness for testing the VM vsock path from the host, not the final
dashboard session protocol.

## Connection Negotiation

Local clients (the dashboard container and the server OOBE) connect to Tetra
over the Unix socket `/run/tetra/tetra.sock` (`tetra agent-serve`) and speak the
session protocol described in [auth-protocol.md](auth-protocol.md): users log
in through Tetra and each request carries a session token. Module commands are
sent with the `module.dispatch` operation using the envelope documented below.
Production installs do not listen on the network.

An outbound connection to a remote control plane is optional and ships
disabled. It runs only while `remote.enabled` is `true` in
`/etc/tetra/tetra.json`, and turning it off drops a live session. On regular
hosts this is WSS with mTLS. When the agent runs inside a VM, the same JSON frame protocol may
be carried over a virtio-vsock stream to the VM host so the VM can be controlled
from the same dashboard interface without exposing guest networking.

The repository includes an outbound WSS client, run by `tetra agent-serve` when
`remote.enabled` is set, or standalone via `tetra agent-connect`. The
JSON command envelope documented below is the stable application payload that
the transport carries.

Transport configuration:

```json
{
  "control_plane_url": "wss://dashboard.example.com/tetra/agent",
  "client_cert_path": "/var/lib/tetra/remote/client.crt",
  "client_key_path": "/var/lib/tetra/remote/client.key",
  "server_ca_path": "/var/lib/tetra/remote/server-ca.crt"
}
```

VM guest agent using host vsock CID:

```json
{
  "control_plane_url": "vsock://host:2048"
}
```

VM guest agent using an explicit numeric CID:

```json
{
  "control_plane_url": "vsock://2:2048"
}
```

Fields:

- `control_plane_url`: Endpoint the agent connects to. Supported schemes are
  `wss://`, `ws://`, and `vsock://CID:PORT`.
- `client_cert_path`: Agent client certificate for mTLS. Required for WSS.
- `client_key_path`: Private key for the client certificate. Required for WSS.
- `server_ca_path`: CA bundle used to verify the dashboard/control-plane server
  certificate. Required for WSS.

Run the outbound agent. After `tetra enroll` no flags are needed; `--config`
and `--host-id` override the enrollment:

```sh
tetra agent-connect
tetra agent-connect --config /etc/tetra/agent-transport.json --host-id host-01
```

For `vsock://` endpoints, `CID` may be numeric or one of the aliases
`hypervisor` (`0`), `local` (`1`), or `host` (`2`). VM guest agents usually use
`vsock://host:PORT`; the VM host is responsible for accepting that stream and
routing frames to the dashboard/control plane session for the matching VM.

### Recommended Lifecycle

1. `enroll`: `tetra enroll` (only while `remote.enabled` is true) sends a CSR
   with the `clientAuth` extended key usage. After approval the controller
   returns the signed client certificate, its server CA, a stable host id and
   the `wss://` URL. See [remote-enrollment.md](remote-enrollment.md).
2. `connect`: The agent opens `control_plane_url`. For WSS, it uses mTLS and
   the dashboard verifies the client certificate. For vsock, the host-side
   acceptor maps the stream to the VM inventory record before forwarding frames
   to the dashboard.
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

### Host-to-Guest Vsock Smoke Test

Inside the VM guest:

```sh
tetra agent-vsock-serve --port 2048
```

From the VM host, connect to the guest CID:

```sh
printf '%s' '{"id":"cmd-1","module":"settings","action":"get_system","payload":{}}' \
  | socat - VSOCK-CONNECT:GUEST_CID:2048
```

The smoke-test listener accepts the command envelope directly, without the
outer `{ "type": "command" }` transport frame, so it matches `agent-dispatch`
and the `/dispatch` HTTP development endpoint.

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

Use command authorization separately from transport authentication:

- Only authorized dashboard users should be able to create commands.
- Dangerous actions should require explicit UI confirmation.
- Prefer a dry-run preview before sending a mutating command without
  `"dry_run": true`.
- Record the dashboard user, command id, host id, module, action, payload hash,
  and response outcome in an audit log.

The `signature` field in `AgentCommand` is reserved for signed command
envelopes. The current dispatcher only rejects an empty signature string; full
signature verification is future transport/policy work.

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
- `signature`: Optional command signature. Empty string is rejected. Full
  signature verification is transport/policy work and is not implemented here.

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
      "actions": ["capabilities", "get_system"]
    }
  ]
}
```

Every module also supports:

- `capabilities`: Returns that module's `ModuleInfo`.
- `plan`: Returns module metadata and echoes the requested payload. This is a
  lightweight planning endpoint, not a dry-run replacement.

## Shared Conventions

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

The enabled module set depends on build features. Default features currently
include `apps`, `files`, `recipes`, `selinux`, `services`, and `quadlets`.

Request payloads are plain JSON objects. Payload types shared across modules —
such as `SelinuxOptions`, `ServiceScope`, and the `apps` module's `App*`
requests — are defined in `src/types.rs` and deserialized with `serde`.

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
- `write`

`read` payload:

```json
{ "path": "/etc/example.conf" }
```

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
`volume`, `pod`, `kube`) and `file` companion resources. Companion file
resources are intended to be installed through `quadlets.install.files`, under
the mutable companion-file bundle directory.

`render_inline` payload:

```json
{
  "recipe": "recipe_id: nginx-site\nname: Nginx static site\nversion: 0.1.0\n...",
  "templates": {
    "containers/nginx-site.container.tera": "[Container]\nContainerName={{ app_id }}\n"
  },
  "values": {
    "app_id": "demo-web"
  }
}
```

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
`render_inline`, and returns resolved parameter context without rendering
templates.

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
- `write`
- `delete`
- `validate`
- `install`
- `list_files`

Shared payload fields:

- `scope`: `"user"` or `"system"`. Defaults to `"user"`.
- `base_dir`: Optional override. Useful for tests and custom deployments.
- `files_base_dir`: Optional override for companion files.

Default Quadlet unit directories:

- User scope: `$HOME/.config/containers/systemd`
- System scope: `/etc/containers/systemd`

Default companion file directories:

- User scope: `$XDG_DATA_HOME/tetra/quadlets` or `$HOME/.local/share/tetra/quadlets`
- System scope: `/var/lib/tetra/quadlets`

During `install`, companion files are written under a per-Quadlet bundle directory
derived from the first Quadlet resource name. For example, `app.container` companion
files default to `/var/lib/tetra/quadlets/app` in system scope.

Supported Quadlet filename extensions:

- `.container`
- `.kube`
- `.network`
- `.pod`
- `.volume`

`list` payload:

```json
{ "scope": "user" }
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

`list_files` payload:

```json
{ "scope": "user" }
```

`list_files` returns all regular files under the selected base directory, including
companion files:

```json
{
  "base_dir": "/home/example/.config/containers/systemd",
  "files_base_dir": "/home/example/.local/share/tetra/quadlets",
  "files": [
    {
      "filename": "app.container",
      "path": "/home/example/.config/containers/systemd/app.container",
      "quadlet": true
    },
    {
      "filename": "app/index.html",
      "path": "/home/example/.local/share/tetra/quadlets/app/index.html",
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
  "scope": "user",
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
the `quadlets` module). The manifest records the recipe source, parameter
values, installed unit filenames, and companion files so `update` can
re-render and `remove` can clean up without the caller resending the recipe.

Request payloads deserialize into the `App*` types in `src/types.rs`
(`AppCreateRequest`, `AppUpdateRequest`, `AppGetRequest`, `AppListRequest`,
`AppRequest` for `remove`), and the manifest is the serialized `AppManifest`
type. The recipe source is `AppRecipeSource`: exactly one of an inline recipe
(`recipe` plus optional `templates`) or an on-disk recipe (`recipe_path` plus
optional `templates_dir`).

Actions:

- `list`
- `get`
- `create`
- `update`
- `remove`

App names may contain letters, digits, `.`, `_`, and `-`, and must not start
with `.` or `-`.

`create` payload (inline recipe):

```json
{
  "name": "my-site",
  "scope": "user",
  "recipe": "id: nginx-site\n...",
  "templates": {
    "app.container": "[Container]\nImage=docker.io/nginx:alpine\n"
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
directory path (e.g. `/var/lib/tetra/quadlets/my-site`) so templates can
bind-mount companion files with `Volume={{ bundle_dir }}/...` without the
caller knowing the agent's layout. An explicitly supplied `bundle_dir`
always wins, and recipes that do not declare the parameter are unaffected
(undeclared values never reach the render context).

`create` renders the recipe, writes the Quadlet units and companion files,
writes `<bundle>/app.json`, optionally applies SELinux contexts to the bundle,
and — unless `converge` is `false` — runs `systemctl daemon-reload`, then
enables and starts the derived services. Service names are derived from unit
filenames: `.container` and `.kube` units map to `<stem>.service`, `.pod`
units to `<stem>-pod.service`; network and volume units have no service.

Response:

```json
{
  "app": {
    "version": 1,
    "name": "my-site",
    "scope": "user",
    "recipe_id": "nginx-site",
    "recipe_version": "0.1.0",
    "recipe": { "source": "inline", "recipe": "...", "templates": {} },
    "values": { "app_id": "my-site" },
    "units": ["my-site.container"],
    "files": ["index.html"],
    "created_at": 1750000000,
    "updated_at": 1750000000
  },
  "base_dir": "/home/example/.config/containers/systemd",
  "bundle_dir": "/home/example/.local/share/tetra/quadlets/my-site",
  "manifest_path": "/home/example/.local/share/tetra/quadlets/my-site/app.json",
  "units": ["my-site.container"],
  "files": ["index.html"],
  "services": ["my-site.service"],
  "systemd": [],
  "selinux": [],
  "written": true,
  "dry_run": false
}
```

`list` payload:

```json
{ "scope": "user" }
```

Returns one summary per app plus an `invalid` array naming bundle directories
whose manifest could not be read (corrupted bundles or stray unmanaged
directories):

```json
{
  "files_base_dir": "/home/example/.local/share/tetra/quadlets",
  "apps": [
    {
      "name": "my-site",
      "recipe_id": "nginx-site",
      "recipe_version": "0.1.0",
      "scope": "user",
      "units": ["my-site.container"],
      "services": ["my-site.service"],
      "created_at": 1750000000,
      "updated_at": 1750000000,
      "bundle_dir": "/home/example/.local/share/tetra/quadlets/my-site"
    }
  ],
  "invalid": []
}
```

`get` payload:

```json
{ "name": "my-site", "scope": "user" }
```

Returns the full manifest plus the unit and companion-file listings (each with
its absolute path and an `exists` flag) and the derived services.

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
rendered, rewrites the manifest, and restarts the derived services when
`converge` is enabled.

`remove` payload:

```json
{
  "name": "my-site",
  "scope": "user",
  "converge": true,
  "dry_run": true
}
```

Stops and disables the derived services (failures are reported inline in the
`systemd` array and tolerated), deletes the Quadlet units, runs
`daemon-reload`, and removes the bundle directory. Volumes created by Podman
for the app's `.volume` units are intentionally preserved.

`create`, `update`, and `remove` all honor `dry_run`, which previews the file
writes and the exact `systemctl` commands without changing the host. Setting
`converge: false` skips systemd interaction entirely, which is useful for
staging files on hosts without systemd.

### services

Feature: `services`

Backed by `systemctl` and `journalctl`.

Actions:

- `list`
- `status`
- `logs`
- `start`
- `stop`
- `restart`
- `enable`
- `disable`

`list` payload (`scope` is optional and defaults to `system`):

```json
{ "scope": "user" }
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

Mutation payload:

```json
{ "service": "sshd.service", "dry_run": true }
```

### selinux

Feature: `selinux`

Backed by `sestatus`, `getenforce`, `getsebool`, `setsebool`, `semanage`, and
`restorecon`.

Actions:

- `status`
- `enforce`
- `booleans`
- `set_boolean`
- `file_contexts`
- `add_file_context`
- `delete_file_context`
- `restore_context`

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
- `mount`
- `unmount`
- `configure`

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

### samba

Feature: `samba`

Actions:

- `list_shares`
- `get_config`
- `set_config`
- `reload`
- `enable`
- `disable`

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

### nfs

Feature: `nfs`

Actions:

- `list_exports`
- `get_config`
- `set_config`
- `reload`
- `enable`
- `disable`

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

### network

Feature: `network`

Actions:

- `interfaces`
- `status`
- `dns`
- `routes`
- `configure` (privileged)
- `confirm` (privileged)
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
`activation_error` (or `null`), `addresses_before` and `addresses_after`.

Safe apply: before activating, Tetra records the interface's routable
addresses. If none of them is present again shortly after activation, the
response has `"confirmation_required": true`, a `confirmation_token`, and
`rollback_in_seconds` (60). Unless the caller sends `confirm` within that time,
Tetra restores the previous keyfile (or deletes the new one) and reactivates
the previously active profile. Only one change can await confirmation at a
time. The pending rollback is held in memory, so a Tetra restart or reboot
inside the window keeps the new configuration.

`confirm` payload:

```json
{ "token": "..." }
```

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

### podman

Feature: `podman`

Actions:

- `containers`
- `inspect`
- `images`
- `volumes`
- `networks`
- `logs`
- `start`
- `stop`
- `restart`
- `remove`

List actions return raw command output plus parsed JSON in `data`.

`inspect` returns `podman inspect NAME` output in `data`.

`inspect` payload:

```json
{ "name": "app" }
```

`logs` payload:

```json
{ "name": "app", "lines": 100 }
```

Mutation payload:

```json
{ "name": "app", "dry_run": true }
```

### users

Feature: `users`

Actions:

- `list`
- `groups`
- `status`
- `create`
- `update`
- `delete`
- `set_password`
- `set_authorized_keys`
- `add_admin`

Every action except `list` and `status` is privileged.

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
- `start`
- `stop`
- `restart`
- `create`
- `delete`

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
    "scope": "user",
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
    "dry_run": true
  }
}
```
