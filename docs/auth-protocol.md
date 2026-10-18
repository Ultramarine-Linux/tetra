# Tetra Session Protocol (local socket)

This is the API local clients (the dashboard and the server OOBE) use on
`/run/tetra/tetra.sock`. Tetra is the only authority for login and
authorization: it verifies passwords, TOTP codes and passkeys, issues session
tokens, and checks every request against the caller's role and grants. Local
clients only hold Tetra-issued tokens.

For how the dashboard should drive these operations, see
[dashboard-auth-guide.md](dashboard-auth-guide.md). Module actions themselves
(`services.list`, `users.create`, ...) are documented in
[agent-protocol.md](agent-protocol.md).

Protocol version: `2026-10-session-v1`.

## Connection

1. Connect to `/run/tetra/tetra.sock` and open a WebSocket over the stream
   (the HTTP `Host` and path are ignored; with Node's `ws`, use
   `ws+unix:///run/tetra/tetra.sock`).
2. Tetra reads the peer's credentials (`SO_PEERCRED`) and identifies the
   client:
   - the UID of `ultramarine-dashboard` is the **dashboard**,
   - the UID of `ultramarine-oobe` is the **OOBE**,
   - anyone else, root included, gets an `error` frame (`forbidden`) and the
     connection is closed.

   The account names can be changed with `tetra agent-serve
   --dashboard-user/--oobe-user`. The socket is `root:tetra 0660`, so both
   clients must also have the `tetra` group, which has the fixed GID 241
   (`systemd/tetra.sysusers.conf`; the dashboard Quadlet uses `GroupAdd=241`).
3. Tetra sends `hello`:

```json
{
  "type": "hello",
  "protocol_version": "2026-10-session-v1",
  "client": "dashboard",
  "host_fingerprint": "base64url Ed25519 public key",
  "setup_required": false,
  "passkeys_available": true
}
```

The controller-key login (Ed25519 challenge, signed commands) is **not**
accepted on the local socket. It remains only on the development TCP listener
(`agent-ws-serve`, `dev-listener` feature). Remote controllers use the outbound
mTLS connection, which is unchanged.

## Frames

Requests:

```json
{
  "type": "request",
  "id": "c0ffee",
  "token": "tts_…",
  "op": "module.dispatch",
  "params": { "module": "services", "action": "list", "payload": {} }
}
```

- `id`: any string; echoed in the response. Use unique ids, because requests
  run concurrently and responses can arrive out of order.
- `token`: the session token. Required for every operation except the ones
  marked "no token" below.
- `params`: operation parameters. Missing params mean `{}`. Unknown fields are
  rejected.

Responses:

```json
{ "type": "response", "id": "c0ffee", "ok": true, "result": { } }
{ "type": "response", "id": "c0ffee", "ok": false,
  "error": { "code": "forbidden", "message": "…", "retry_after": 30 } }
```

A frame that is not valid JSON gets `{"type": "error", "error": {...}}`
without an `id`.

### Error codes

| Code | Meaning |
| --- | --- |
| `bad_request` | Malformed or unknown parameters. |
| `unknown_operation` | No such `op`. |
| `unauthenticated` | Missing, expired or revoked token. Log in again. |
| `forbidden` | Authenticated, but not allowed. |
| `invalid_credentials` | Wrong password, code or passkey; unknown, ineligible or locked account. Deliberately not more specific. |
| `password_expired` | Right password, but it has expired. Change it on the console or over SSH. |
| `rate_limited` | Retry after `retry_after` seconds. |
| `passkeys_unavailable` | The server is in IP mode or has no access configuration. |
| `wrong_client` | The token or operation belongs to the other local client. |
| `setup_complete` | Setup has already completed. |
| `setup_incomplete` | Setup cannot complete yet (no eligible administrator). |
| `not_found` | No such session, passkey, enrollment, account or launcher entry (including entries the caller cannot see). |
| `conflict` | Already enrolled or already registered. |
| `action_failed` | The module action ran and failed; `message` has its error. |
| `queue_full` | Tetra's command queue is full; retry after backoff. |
| `internal` | Tetra failed; details are in the journal only. |

## Who can log in

An account can log in when all of these hold, checked on every login
(passkeys included) and again on every request:

- UID is at least `UID_MIN` from `/etc/login.defs`;
- the shell is listed in `/etc/shells` and is not `nologin`/`false`;
- the shadow entry is not locked (`!`, `*`) and not expired;
- it is not `ultramarine-apps`;
- PAM's account stack (`/etc/pam.d/ultramarine-dashboard`) accepts it.

Locking, deleting or renaming an account ends its sessions on the next
request.

## Sessions

A token (`tts_` + 43 characters) is issued only after full authentication:

- password, plus TOTP or a recovery code if the user enrolled TOTP; or
- a passkey alone; or
- the setup code (setup session, OOBE only).

Tokens are bound to the client they were issued to. User sessions last 12
hours and expire after 1 hour without use; setup sessions last 2 hours. Tetra
stores only token hashes; sessions survive a Tetra restart.

## Operations

### Login (no token)

**`auth.password`** `{username, password, remote_addr?}`

`remote_addr` is the browser's address, passed to PAM as `PAM_RHOST`.

```json
{ "status": "authenticated", "token": "tts_…",
  "session": { "id": "…", "client": "dashboard", "kind": "user", "method": "password",
               "uid": 1000, "username": "alice", "created_at": 0, "expires_at": 0,
               "last_seen": 0, "current": false },
  "user": { "uid": 1000, "username": "alice", "admin": false } }
```

or, when TOTP is enrolled:

```json
{ "status": "second_factor_required", "pending": "…",
  "methods": ["totp", "recovery_code"], "expires_at": 0 }
```

Failures: `invalid_credentials`, `password_expired` (only for accounts that
may log in to the dashboard; for others a right but expired password is
`invalid_credentials`). Repeated wrong passwords lock password logins to the
dashboard through `pam_faillock`. The dashboard keeps its own tally in
`/var/lib/tetra/faillock`, so dashboard failures never lock console or SSH
logins and theirs never lock the dashboard. `deny=` and `unlock_time=` come
from `/etc/security/faillock.conf`; unlock with
`faillock --dir /var/lib/tetra/faillock --user NAME --reset`. A lockout does
not block passkey logins: they run only the account stack, which has no
`pam_faillock`, and Tetra limits passkey ceremonies per address instead.

**`auth.second_factor`** `{pending, code}` or `{pending, recovery_code}`

Returns the `authenticated` result. A pending login lasts 5 minutes and allows
5 wrong codes. Wrong codes are also counted per account, across logins and
restarts: after 10 wrong TOTP codes in a row each further TOTP attempt waits
twice as long as the last (capped at 15 minutes) and gets `rate_limited`
without the code being checked; the pending login is kept. Recovery codes are
too strong to guess and keep working during the wait. A right code resets the
count. The same limit applies to the operations that need a current code
(`account.totp_*`).
A TOTP code is accepted only once; recovery codes are single use.

**`auth.passkey_begin`** `{username?, conditional?, remote_addr?}`

```json
{ "ceremony": "…", "options": { "publicKey": { … } }, "expires_at": 0 }
```

`options` is a WebAuthn `PublicKeyCredentialRequestOptions` wrapper to pass to
`navigator.credentials.get()` (after base64url decoding the binary fields).

The primary form has no `username`: a discoverable challenge with an empty
`allowCredentials`, and Tetra identifies the user from the credential's user
handle. Passkeys are registered as discoverable credentials where the
authenticator can store one, so this works for them. `conditional: true`
keeps `mediation: "conditional"` for autofill UI.

With a `username` (the fallback for keys that could not store a discoverable
credential) the challenge lists that user's credentials, and never uses
conditional mediation. For any other `username` (unknown, not allowed to log
in, or without passkeys) it lists one decoy credential derived from the name;
no authenticator holds it.

Ceremonies expire after 5 minutes and are single use. `remote_addr` is the browser's IP address: each
address (IPv6 by `/64`) may have 16 pending ceremonies, and a 17th replaces
its oldest, so one client cannot use up the shared limit of 4096. Without a
valid IP address the ceremony only counts against the shared limit. The decoy
looks like one platform passkey, so it hides users with exactly that; a user
with several passkeys or security keys can still be told apart.

**`auth.passkey_finish`** `{ceremony, credential, remote_addr?}`

`credential` is the `PublicKeyCredential` from the browser, JSON-encoded.
Returns the `authenticated` result with `method: "passkey"`.

### Setup (no token)

**`setup.status`** `{}` → `{setup_required, passkeys_available}`. With a setup
or administrator token it also returns `admin_exists`.

**`setup.redeem`** `{code}` (OOBE only)

```json
{ "status": "authenticated", "token": "tts_…", "session": { "kind": "setup", … },
  "admin_exists": false }
```

Errors: `wrong_client` (not the OOBE), `invalid_credentials`,
`rate_limited` (3 free attempts, then a doubling wait capped at 5 minutes; the
code is replaced after 20 wrong attempts), `setup_complete`.

### App access check (no token)

**`launcher.can_access`** `{uid, id}` (dashboard only) → `{allowed}`

Whether the account `uid` may open launcher entry `id`, by the same rules as
`launcher.list` (see [Launcher](#launcher)). For the dashboard's OIDC provider
and Caddy `forward_auth`, which can run without the user's session (for
example an app refreshing its tokens). It takes no token because it only
answers yes or no about an entry, and only to the dashboard; the OOBE gets
`wrong_client`. `allowed` is `false` for unknown or hidden entries, unknown
UIDs and accounts that may not log in (see [Who can log in](#who-can-log-in)),
so the answer does not reveal whether an entry exists.

### Session

| Op | Params | Result |
| --- | --- | --- |
| `session.info` | | `{session, user, permissions}`; `permissions` is `{"all": true}` for admins, `{page: level}` for users, `{"setup": [...]}` for the setup session |
| `session.logout` | | `{revoked: 1}` |
| `session.list` | `uid?` (admins only for other users) | `{sessions: [...]}` |
| `session.revoke` | `id` | `{revoked}`; own sessions, or any user session for admins |

### Account (user sessions)

| Op | Params | Result |
| --- | --- | --- |
| `account.status` | | `{totp_enrolled, recovery_codes_left, passkeys, passkeys_available}` |
| `account.totp_begin` | | `{enrollment, secret, otpauth_uri, expires_at}`; `conflict` if already enrolled |
| `account.totp_confirm` | `enrollment, code` | `{recovery_codes: [10 codes]}`; shown once |
| `account.totp_disable` | `code` or `recovery_code` | `{totp_enrolled: false}` |
| `account.recovery_regenerate` | `code` or `recovery_code` | `{recovery_codes}` |
| `account.passkey_register_begin` | `name?` | `{ceremony, options, expires_at}`; pass `options` to `navigator.credentials.create()`. Asks for a discoverable credential (`residentKey: "preferred"`), so usernameless login works; keys that cannot store one still register |
| `account.passkey_register_finish` | `ceremony, credential, name?` | `{id, name, created_at}` |
| `account.passkey_list` | | `{passkeys: [{id, name, created_at, last_used_at}]}` |
| `account.passkey_remove` | `id` | `{removed}` |

### Authorization

| Op | Params | Result |
| --- | --- | --- |
| `authz.catalog` | | `{pages: [{page, label, grantable: ["view", "manage"], default}]}`; `label` is the name to show, such as `"System services"` |
| `admin.grants_get` | `uid?` | one user's `{uid, grants, effective}` or `{grants: {uid: {page: level}}}` |
| `admin.grants_set` | `uid, grants: {page: "view" \| "manage" \| null}` | `{uid, grants, effective}`; `null` removes a grant |
| `admin.sessions_revoke` | `uid` | `{revoked}`; also invalidates sessions not yet loaded |
| `admin.actions` | `limit?` (100), `origin?` (`local`, `setup`, `remote`) | `{actions: [...]}`, newest first |

`admin.*` operations need an administrator.

### Launcher

The launcher is the dashboard's Services page: the apps a user can open. Each
entry has an id, a name, an icon, a URL, a visibility, a `public` flag and a
source.

| Op | Params | Result |
| --- | --- | --- |
| `launcher.list` | | `{entries: [entry]}`, the entries the caller can see, in stored order |
| `launcher.get` | `id` | `{entry}`; `not_found` for missing entries and for entries the caller cannot see alike |
| `launcher.set` | `id?, entry: {name, icon, url, visibility, public}` | `{entry}`; without `id` adds an entry, with `id` replaces it (`not_found` if there is none) |
| `launcher.remove` | `id` | `{removed: id}` |
| `launcher.public_get` | | `{enabled, path}` |
| `launcher.public_set` | `enabled` | `{enabled, path}` |

`launcher.list` and `launcher.get` need `launcher: view`, which every user
has. The other operations need an administrator. The setup session has no
launcher. Changes are recorded in the action log.

An entry as administrators see it:

```json
{ "id": "Vb3sQe1xKp0a", "name": "Photos", "icon": "lucide:image",
  "url": "https://photos.example.com/",
  "visibility": { "kind": "members", "users": ["alice"], "groups": ["media"] },
  "public": false, "source": "manual" }
```

Everyone else gets `id`, `name`, `icon` and `url` only: no visibility,
public flag, source, unit names, status or logs.

- `visibility` is `{"kind": "everyone"}` (every user who can log in),
  `{"kind": "admins"}`, or `{"kind": "members", "users": [...], "groups":
  [...]}` (the listed usernames and members of the listed groups, including
  primary groups). Administrators see and can open every entry. Group
  membership is read on every request.
- `icon` is `null`, an icon name (up to 64 letters, digits, `-`, `_`, `.`,
  `:`; the dashboard decides how to draw it), or a small image as a
  `data:image/{png,jpeg,gif,webp,svg+xml};base64,…` URL of at most 64 KiB.
- `url` is any absolute `http` or `https` URL with a host, stored as given.
- `source` is `manual` for entries added with `launcher.set`. `catalog` is
  reserved for apps installed from the catalog (not available yet); their URL
  is built from the app's route and `access.json` (domain mode:
  `https://<app>.<hostname>/` or `https://<hostname>/<path>/`; IP mode:
  `https://<ip>:<port>/`, IPv6 in brackets), so it follows changes of the
  access mode. Replacing an entry keeps its source.

**Public page.** When an administrator enables it with
`launcher.public_set {enabled: true}`, Tetra writes a static page listing the
entries marked `public` (names, icons and URLs only, whatever their
visibility) to `/var/lib/tetra-public/index.html` (`tetra agent-serve
--public-dir`). The dashboard's Caddy site serves it without a login at
`/public/`. It is off by default; while it is off the file does not exist and
the route answers 404. Tetra regenerates the page whenever entries or the
setting change, after `access.set`, and when it starts. The page loads nothing
from other origins (its CSP allows only inline styles and `data:` images).

### Access and setup completion

| Op | Params | Result |
| --- | --- | --- |
| `access.get` | | `{access, passkeys_available}` |
| `access.set` | `mode: "domain" \| "ip", hostname, port?, dashboard_upstream?` | `{access, passkeys_available, dashboard_site}` |
| `setup.complete` | | `{complete: true}` |

`access.set` and `setup.complete` need the setup session or an
administrator.

- `access.set` stores `/var/lib/tetra/access.json`, then regenerates the
  dashboard's Caddy site (`/etc/caddy/tetra-sites/00-ultramarine-dashboard.caddy`)
  and reloads Caddy. The site also routes `/public/` to the launcher's
  public page.
- Domain mode (custom domains and Tailscale `*.ts.net` names) uses automatic
  HTTPS and enables passkeys, with the hostname as the RP ID and
  `https://hostname[:port]` as the origin.
- IP mode uses `tls internal` and disables passkeys.
- `dashboard_upstream` defaults to `127.0.0.1:3972`.
- Changing the hostname invalidates passkeys registered under the old one.

`setup.complete` requires at least one eligible administrator. It writes
`/var/lib/tetra/setup-complete`, which disables the setup code permanently,
removes the published code, and ends every setup session.

### Module actions

**`module.dispatch`** `{module, action, payload?}`

Runs a module action (see [agent-protocol.md](agent-protocol.md)). The result
is the action's payload; a failed action is `action_failed`. Unprivileged
actions run as the session's user through `runuser`; privileged ones as root.
Every dispatched action is recorded in the action log.

## Authorization

- **Administrators** (members of `ultramarine-admin` or `wheel`, checked on
  every action) may run everything.
- **Other users** have `launcher: view` by default (the Services page: the
  apps shared with them), plus their grants. `manage` implies `view`.
- **The setup session** may run only OOBE operations: `settings.get_system`,
  `settings.set_hostname`, `network.configure` and `network.confirm`, all of
  `reverse_proxy.*`,
  `users.list/status/groups/create/update/set_password`, and
  `agent.capabilities` (list in `src/auth/authz.rs`, `SETUP_ALLOWED`).
- `capabilities` and `plan` of every module are open to any session.
- Actions not in the table are administrator-only.

| Page | `view` | `manage` (grantable) | Administrator only |
| --- | --- | --- | --- |
| `launcher` (default) | `launcher.list/get` | — | `launcher.set/remove/public_get/public_set` |
| `system_services` | `services.list/status/logs` (systemd units and their journal; not a default, grant it explicitly) | — | start, stop, restart, enable, disable, daemon_reload |
| `apps` | `apps.list/get`, `quadlets.list/read/validate/list_files`, `recipes.render_inline/context_inline` | — | apps create/update/remove, quadlets write/delete/install, `recipes.render/context` (read paths as root) |
| `containers` | `podman.containers/inspect/images/volumes/networks/logs` | — | podman start/stop/restart/remove |
| `storage` | `storage.list/status/zfs` | — | `storage.mount/unmount/configure` |
| `sharing` | `samba.list_shares/get_config`, `nfs.list_exports/get_config` | `samba/nfs.set_config/reload` | samba/nfs enable, disable |
| `network` | `network.interfaces/status/dns/routes`, `reverse_proxy.list/render` | `reverse_proxy.write/delete/reload` | `network.get_config/set_config/reload/configure/confirm` |
| `virtual_machines` | `virtual_machines.list/status/logs` | — | start, stop, restart, create, delete |
| `settings` | `selinux.status/booleans/file_contexts` | — | `settings.set_hostname`, SELinux changes |
| `users` | `users.list/status/groups` | — | create, update, delete, set_password |
| `files` | — | — | `files.read/write` |

Payload fields that point an action at arbitrary host paths are
administrator-only: `config_dir` on `reverse_proxy` actions and
`base_dir`/`files_base_dir` on `quadlets` and `apps` actions. The setup session
and granted users always get the default directories. Stored grants that are
no longer grantable (such as `files: view` from an earlier release) are
ignored. Grants stored under the page's earlier name, `services`, are read as
`system_services`.

Managing users, reading or writing files (the files module runs as root on
any path), settings or storage (mounting is root-equivalent), and
anything that manages rootful systemd units, containers or VMs, is never
grantable. Apps are currently installed as
system-scope units, so app management is administrator-only until apps run
rootless under `ultramarine-apps`.

Remote controllers (the outbound mTLS connection) are authorized as a
`RemoteController` principal that may run everything. Each of their actions
is recorded with `origin: "remote"`.

## First-boot setup code

- Until `/var/lib/tetra/setup-complete` exists, the server is in setup mode,
  even if an administrator already exists (for example one created by
  Readymade).
- `tetra-setup-code.service` runs `tetra setup code --publish` at boot. It
  generates the code once (`XXXX-XXXX`, sealed in
  `/var/lib/tetra/auth/setup-code.json`) and writes it to
  `/run/tetra/setup-code` (root-only, for the console screen) and
  `/run/issue.d/50-tetra-setup.issue` (getty login banner). It is never shown
  over SSH.
- The code stays the same across reboots until setup completes or the
  wrong-code limit replaces it. Tetra republishes a replaced code itself.
- `sudo tetra setup code` prints the current code (and, like `--publish`,
  writes it to the console, so the printed code is always the one shown).
  Publishing only creates the files; `/run/tetra` keeps the socket unit's
  `0755` mode so the OOBE can reach the socket.
- `sudo tetra setup complete` finishes setup from the console, with the same
  check as `setup.complete` (an eligible administrator must exist). Use it on
  upgraded hosts and development machines that have no OOBE run.

## Stored state

All under `/var/lib/tetra` (`0700`, files `0600`, root only):

| Path | Contents |
| --- | --- |
| `auth/store-key.cred` | 32-byte store key sealed with `systemd-creds` (TPM2 + host key when a TPM exists, no PCR binding) |
| `auth/users/<uid>.json` | TOTP secret (encrypted with the store key), recovery code hashes, passkeys, session epoch |
| `auth/grants.json` | Grants per UID |
| `auth/sessions.json` | Session token hashes |
| `auth/setup-code.json` | Encrypted setup code and wrong-attempt state |
| `faillock/` | `pam_faillock` tally for dashboard password logins only |
| `access.json` | Access mode, hostname, port, dashboard upstream |
| `launcher.json` | Launcher entries and the public page setting |
| `setup-complete` | Setup completion marker |
| `audit/actions.jsonl` | Action log (rotated at 4 MiB) |

The public page is the one launcher file outside this directory:
`/var/lib/tetra-public/index.html` (`0644`, directory `0755`), so Caddy can
read it. It holds only what the page shows.

Every file carries `schema` and `compat` versions. A Tetra build refuses a file
whose `compat` is newer than it understands, and keeps unknown fields when it
rewrites a file, so rolling back one release keeps working. Values a newer
release added to a stored list (a permission page or level, a session's
client, kind or method, a launcher visibility, source or route kind) are kept
as they are and grant nothing: unknown grants are ignored, unknown sessions
are not accepted (and dropped once their `expires_at` passes), entries with
an unknown visibility are shown to administrators only, and unknown sources
or route kinds open the stored URL. An `access.json` with an unknown mode
reads as no access configuration until `access.set` replaces it. Action log
lines that cannot be read are left out of `admin.actions`.

## Console recovery

```sh
sudo tetra auth reset-2fa alice            # TOTP and recovery codes
sudo tetra auth reset-2fa alice --passkeys # also passkeys
```

Both log the user out everywhere. They do not need the store key, so they
also recover users whose TOTP secrets can no longer be decrypted (for example
after clearing the TPM).
