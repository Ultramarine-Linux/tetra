# Tetra Session Protocol (local socket)

This is the API local clients (the dashboard and the server OOBE) use on
`/run/tetra/tetra.sock`. Tetra is the only authority for login and
authorization: it verifies passwords, TOTP codes and passkeys, issues session
tokens, and checks every request against the caller's role and grants. Local
clients only hold Tetra-issued tokens. The development-only `agent-ws-serve`
listener serves this same protocol on loopback TCP; it does not introduce a
second authentication system.

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

## Development TCP listener

Build with `--features dev-listener`, then run `tetra agent-ws-serve` to serve
the same session protocol over WebSocket on loopback TCP. Use the same
privileges and PAM setup as the daemon (usually root):

```sh
cargo build --features dev-listener
sudo target/debug/tetra agent-ws-serve \
  --listen 127.0.0.1:7780 --client dashboard
```

`--listen` rejects non-loopback addresses. TCP has no peer credentials, so
`--client dashboard|oobe` (default `dashboard`) is applied to every connection;
any local process that can connect is treated as that client. Every request
still uses the session tokens and authorization described below. The listener
is development-only, has no TLS, and must not be exposed to other hosts. Use
the Unix socket in production. Remote controllers use the outbound mTLS
connection, not this local session protocol.

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
| `reauth_required` | The operation adds or removes a way to log in and the session is more than 10 minutes old; log in again and retry. |
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
request. A successful `users.set_password` or `users.delete` through
`module.dispatch` (not a dry run) also ends every session of the named
account right away, except the caller's own.

## Sessions

A token (`tts_` + 43 characters) is issued only after full authentication:

- password, plus TOTP or a recovery code if the user enrolled TOTP; or
- a passkey alone; or
- the setup code (setup session, OOBE only).

Tokens are bound to the client they were issued to. User sessions last 12
hours and expire after 1 hour without use; setup sessions last 2 hours. A
user may have at most 32 sessions: a new login beyond that ends the user's
least recently used session. Tetra stores only token hashes; sessions survive
a Tetra restart.

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
its oldest, so one client cannot use up the shared limit of 4096. (Clients
forwarded by Tailscale all count as `127.0.0.1`; see
[Clients forwarded by Tailscale](#clients-forwarded-by-tailscale).) Without a
valid IP address the ceremony only counts against the shared limit. The decoy
looks like one platform passkey, so it hides users with exactly that; a user
with several passkeys or security keys can still be told apart.

**`auth.passkey_finish`** `{ceremony, credential, remote_addr?}`

`credential` is the `PublicKeyCredential` from the browser, JSON-encoded.
Returns the `authenticated` result with `method: "passkey"`.

### Setup (no token)

**`setup.status`** `{}` → `{setup_required, passkeys_available}`. With a setup
or administrator token it also returns `admin_exists`.

**`setup.redeem`** `{code, remote_addr?}` (OOBE only)

`remote_addr` is the browser's address as Caddy reported it to the OOBE (the
same field as on `auth.password`). Tetra logs it with every attempt and uses it
for a per-address throttle.

```json
{ "status": "authenticated", "token": "tts_…", "session": { "kind": "setup", … },
  "admin_exists": false }
```

Errors: `wrong_client` (not the OOBE), `invalid_credentials`,
`rate_limited` with `retry_after`, `setup_complete`. Two limits apply:

- **Per address** (only when `remote_addr` is given): 3 free wrong codes, then
  a wait of 30 seconds that doubles with every further wrong code, capped at
  one hour. The source port is ignored (`ip`, `ip:port`, `[ipv6]:port`),
  IPv6 addresses are counted per /64, and every `remote_addr` that is not an
  IP address shares one bucket. Attempts refused here never
  reach the global counter, so one address needs about 11 hours of guessing
  to force a rotation, instead of under an hour. Concurrent attempts from one
  address are checked one after another, so they cannot all slip past the
  check. It does not stop a client that changes its address, and it trusts the
  `remote_addr` the OOBE passes on. Kept in memory.
- **Global** (unchanged): 3 free wrong codes, then a doubling wait capped at 5
  minutes; the code is replaced after 20 wrong attempts. Stored, so it
  survives restarts. This is what stops guessing from many addresses.

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
| `session.info` | | `{session, user, permissions}`; `permissions` is `{"all": true}` for admins, `{page: level}` for users, `{"setup": ["module.action", ...], "operations": [...]}` for the setup session |
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

`account.totp_begin`, `account.passkey_register_begin` and
`account.passkey_remove` need a session from the last 10 minutes
(`reauth_required` otherwise), so a stolen session cannot plant a credential
that outlives it. `totp_disable` and `recovery_regenerate` already need the
second factor itself.

### Authorization

| Op | Params | Result |
| --- | --- | --- |
| `authz.catalog` | | `{pages: [{page, label, grantable: ["view", "manage"], default}]}`; `label` is the name to show, such as `"System services"` |
| `admin.grants_get` | `uid?` | one user's `{uid, grants, effective}` or `{grants: {uid: {page: level}}}` |
| `admin.grants_set` | `uid, grants: {page: "view" \| "manage" \| null}` | `{uid, grants, effective}`; `null` removes a grant |
| `admin.sessions_revoke` | `uid` | `{revoked}`; also invalidates sessions not yet loaded |
| `admin.actions` | `limit?` (100), `origin?` (`local`, `setup`, `remote`) | `{actions: [...]}`, newest first |

`admin.*` operations need an administrator.

The action log (`admin.actions`) records every module action run through
`module.dispatch` or by a remote controller, and the operations
`access.set`, `setup.complete`, `admin.grants_set`, `admin.sessions_revoke`,
`launcher.set`, `launcher.remove` and `launcher.public_set` (as `module`
and `action`, such as `admin` and `grants_set`). An entry is `{at, origin,
client?, uid?, username?, host_id?, command_id, module, action, ok, error?}`.
Requests refused before anything ran (`forbidden`, or `bad_request` for
operations) are not recorded.

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
| `access.set` | `mode: "domain" \| "ip", hostname, port?, dashboard_upstream?, challenge?: "http-01" \| "dns-01", dns_provider?, dns_credentials?` | `{access, passkeys_available, dashboard_url, dashboard_site: {path, contents, changed}, caddy, dashboard_env}` |
| `setup.complete` | | `{complete: true, dashboard_url, handoff_in_seconds, handoff}` |

`access.set` and `setup.complete` need the setup session or an
administrator.

- `access.set` regenerates the dashboard's Caddy site
  (`/etc/caddy/Caddyfile.d/00-ultramarine-dashboard.caddyfile`), stores
  `/var/lib/tetra/access.json` and reloads Caddy (see [Caddy](#caddy)). The
  site also routes `/public/` to the launcher's public page.
- Every parameter (including `dns_credentials`) is checked, and the site,
  the credential files and the dashboard's environment are rendered, before
  anything changes: a `bad_request` leaves the host as it was. Then the site
  is written, then the DNS-01 credentials are replaced or forgotten, then
  `access.json` and the passkey relying party are updated. Reloading Caddy
  and updating the dashboard's `ORIGIN` come last; their failures are
  reported in `caddy.error` and `dashboard_env.error`, not as a failed
  request, because the new configuration is already in place. Concurrent
  `access.set` requests run one after another.
- Domain mode (custom domains and Tailscale `*.ts.net` names) uses automatic
  HTTPS and enables passkeys, with the hostname as the RP ID and
  `https://hostname[:port]` as the origin. Caddy gets certificates for
  `*.ts.net` names from tailscaled, so those take `http-01` (the default),
  never `dns-01`. To reach the dashboard over Tailscale, set the node's
  `*.ts.net` name (from `remote_access.tailscale_up` or `status`) as the
  hostname.
- While Tailscale is set up (`remote_access.tailscale_up` installed its
  `tailscaled.service` drop-in and `tailscale_disable` has not removed it),
  `access.set` refuses to change the port with `conflict`, changing nothing:
  Tailscale forwards the port that was configured when `tailscale_up` ran.
  Run `remote_access.tailscale_disable`, change the port, then
  `remote_access.tailscale_up` again.
- IP mode uses `tls internal` and disables passkeys.
- `port` defaults to 443. Ports 0, 80 (plain HTTP in Caddy), 2019 (Caddy's
  admin endpoint), 6623 (the OOBE's site), 6624 (the OOBE itself) and the
  port of `dashboard_upstream` (3972 by default) are refused with
  `bad_request`: Caddy listens on every address, so it would collide with
  those listeners. The same goes for a `dashboard_upstream` on 443 when
  `port` is omitted.
- `dashboard_upstream` defaults to `127.0.0.1:3972` (`tetra agent-serve
  --dashboard-upstream`). It must be `host:port` and nothing else: an IPv4
  address, a bracketed IPv6 address or a DNS name, and a decimal port, without
  a scheme or path (`bad_request` otherwise). Its port may not be 0, 80,
  2019, 6623 or 6624 either (`bad_request`), since Caddy or the OOBE listens
  there.
- Changing the hostname invalidates passkeys registered under the old one.
- `dashboard_url` is `https://hostname[:port]`, IPv6 addresses bracketed.
- Every `access.set` writes `ORIGIN=<dashboard_url>` to
  `/etc/ultramarine-dashboard/env` (other lines, mode and owner are kept, as
  the file may hold the dashboard's secrets; a new file is root-only `0600`)
  and, if the file changed, restarts `ultramarine-dashboard.service` if it is
  running (`systemctl --no-block try-restart`, as the dashboard may be the
  caller). `dashboard_env` reports `{path, origin, changed, error,
  restart_error}`.

**Certificate challenge.** In domain mode `challenge` defaults to `http-01`.
With `dns-01`, Caddy proves control of the domain through the DNS provider:

- `dns_provider` is one of the caddy-dns modules built into terra-caddy:
  `cloudflare`, `porkbun`, `desec`, `route53`, `hetzner`, `ovh`, `gandi`,
  `linode`, `powerdns`, `rfc2136`, `acmedns`.
- `dns_credentials` is an object keyed as in the module's Caddy JSON config:

  | Provider | Keys (secret ones in bold) |
  | --- | --- |
  | `cloudflare`, `hetzner`, `linode` | **`api_token`** |
  | `porkbun` | **`api_key`**, **`api_secret_key`** |
  | `desec` | **`token`** |
  | `route53` | `access_key_id`, **`secret_access_key`**, `region` (optional) |
  | `ovh` | `endpoint`, `application_key`, **`application_secret`**, **`consumer_key`** |
  | `gandi` | **`bearer_token`** |
  | `powerdns` | `server_url`, **`api_token`** |
  | `rfc2136` | `server`, `key_name`, `key_alg`, **`key`** |
  | `acmedns` | `server_url`, `subdomain`, `username`, **`password`** |

  Unknown or missing keys are `bad_request`. Secrets must be one line;
  the other values may only contain letters, digits and `. - _ : / @ + =`.
- `dns_credentials` may be left out to keep the credentials stored for the
  same provider (for example when only the port changes).
- `dns-01` is refused in IP mode. `dns_provider` and `dns_credentials` are
  refused with `http-01`, and switching to `http-01` deletes the stored
  credentials.

Credentials never appear in `access.json`, a Caddyfile, a response or a log.
Tetra seals them in `/var/lib/tetra/secrets/tetra-dns-credentials.cred` and
writes the secret ones to `/etc/caddy/tetra-dns.env` (`root:caddy`, `0640`) as
`TETRA_DNS_<KEY>`. A drop-in, `/etc/systemd/system/caddy.service.d/50-tetra.conf`,
loads that file with `EnvironmentFile=`, and the site refers to the values as
`{env.TETRA_DNS_<KEY>}` runtime placeholders, so even Caddy's adapted config
holds only the placeholder. Non-secret settings are written into the site
literally, because not every module expands placeholders in them. When the
environment changes, Caddy is restarted with `--no-block` (a restart waits for
requests in flight, and this one may be passing through Caddy); otherwise it is
reloaded. `caddy` reports `{restarted, reloaded, error}`.

**`setup.complete`** requires at least one eligible administrator. It writes
`/var/lib/tetra/setup-complete`, which disables the setup code permanently,
removes the published code, and ends every setup session. Then it hands over
to the dashboard:

1. `systemctl --no-block start ultramarine-dashboard.service` (the unit
   generated from the dashboard's Quadlet). It does not wait for the start,
   which can take minutes when the dashboard's image is pulled first.
2. A transient timer, `tetra-setup-handoff`, runs
   `tetra setup finish-handoff` (with the daemon's `--state-dir` and
   `--caddy-sites-dir`) `handoff_in_seconds` (5) seconds later. That stops
   and disables `ultramarine-server-oobe.service` and
   `tetra-setup-code.service` (one at a time; a unit that is not installed
   is skipped), then removes the OOBE's Caddy site and reloads Caddy. When
   stopping a unit fails, the site stays, so the handoff is retried.

The transient timer does not survive a reboot, and starting it can fail, so
`tetra agent-serve` also finishes the handoff when it starts on a host whose
setup has completed but whose OOBE site is still there; failures are logged.

The response comes back before the OOBE is stopped, so it can show a final
screen with `dashboard_url` (`null` if `access.set` was never called).
`handoff` reports `{dashboard_started, dashboard_error, oobe_stop_scheduled,
oobe_error}`; a failure there does not undo setup completion.
`dashboard_started` means the start job was queued: a dashboard that fails
while starting shows up in `systemctl status ultramarine-dashboard`, not here.

### Module actions

**`module.dispatch`** `{module, action, payload?}`

Runs a module action (see [agent-protocol.md](agent-protocol.md)). The result
is the action's payload; a failed action is `action_failed`, and a full
command queue `queue_full`. Unprivileged actions run as the session's user
through `runuser`; privileged ones, and every action of the setup session, as
root. Module actions run one at a time on the host; a host command that takes
longer than 15 minutes is killed and the action fails. Every dispatched
action that passes authorization is recorded in the action log.

## Authorization

- **Administrators** (members of `ultramarine-admin` or `wheel`, checked on
  every action) may run everything.
- **Other users** have `launcher: view` by default (the Services page: the
  apps shared with them), plus their grants. `manage` implies `view`.
- **The setup session** may run only the module actions the OOBE needs, each
  named individually (list in `src/auth/authz.rs`, `SETUP_ALLOWED`):
  `agent.capabilities`; `settings.set_hostname/set_keymap/set_locale/set_timezone`;
  `users.create/set_password/set_authorized_keys/add_admin`;
  `power.reboot/poweroff`; `network.interfaces/status/scan_wifi/connect_wifi/configure/confirm/pending`;
  `updates.set_policy`; and
  `remote_access.status/tailscale_up/tailscale_disable/cloudflared_set_token/cloudflared_disable`.
  No `services.*`, no raw network configuration (`network.get_config/set_config`),
  no `reverse_proxy.*` and no `users.update` (which can change group
  memberships). `users.add_admin` is refused once an eligible administrator
  exists. `users.set_password`, `users.set_authorized_keys` and
  `users.add_admin` only accept an account the same setup session created with
  `users.create` (not a dry run), and never `root`, so the setup code cannot
  take over an existing account such as an administrator Readymade created,
  or make root, a service account or the installer's user an administrator
  (`SETUP_OWN_ACCOUNTS_ONLY`). Of the socket operations it may only use `session.info`,
  `session.logout`, `setup.status`, `setup.complete`, `access.get`,
  `access.set` and `module.dispatch` (`SETUP_OPERATIONS`); anything else is
  `forbidden`.
- `capabilities` and `plan` of every module, and `settings.get_system`, are
  open to any signed-in user. The setup session gets only the actions listed
  above (`agent.capabilities` among them), so `settings.get_system` and every
  other `capabilities` or `plan` action are `forbidden` for it.
- Actions not in the table are administrator-only.

| Page | `view` | `manage` (grantable) | Administrator only |
| --- | --- | --- | --- |
| `launcher` (default) | `launcher.list/get` | — | `launcher.set/remove/public_get/public_set` |
| `system_services` | `services.list/status/logs` (systemd units and their journal; not a default, grant it explicitly) | — | start, stop, restart, enable, disable, daemon_reload |
| `apps` | `apps.list/get` (`get` shows secret values as `********`), `quadlets.list/validate/list_files`, `recipes.context_inline` | — | apps create/update/remove, quadlets read (unit files hold app secrets)/write/delete/install, `recipes.render/context` (read paths as root), `recipes.render_inline` (templates can loop for a very long time) |
| `containers` | `podman.containers/inspect/images/volumes/networks/logs` (as `ultramarine-apps` by default; `inspect` hides environment values) | — | podman start/stop/restart/remove, `inspect` with `show_env` |
| `storage` | `storage.list/status/zfs` | — | `storage.mount/unmount/configure` |
| `sharing` | `samba.list_shares/get_config`, `nfs.list_exports/get_config` (default config path only) | `samba/nfs.reload` | samba/nfs `set_config` (the files can run commands as root), enable, disable |
| `network` | `network.interfaces/status/dns/routes`, `reverse_proxy.list/render` | `reverse_proxy.write/delete/reload` | `network.get_config/set_config/reload/configure/confirm/pending/scan_wifi/connect_wifi`, `remote_access.*` |
| `virtual_machines` | `virtual_machines.list/status/logs` | — | start, stop, restart, create, delete |
| `settings` | `selinux.status/booleans/file_contexts`, `updates.get_policy` | — | `settings.set_hostname/set_keymap/set_locale/set_timezone`, `updates.set_policy`, `power.reboot/poweroff`, SELinux changes |
| `users` | `users.list/status/groups` | — | create, update, delete, set_password, set_authorized_keys, add_admin |
| `files` | — | — | `files.read/write` |

Payload fields that point an action at arbitrary host paths are
administrator-only (`ADMIN_ONLY_FIELDS`): `config_dir` on `reverse_proxy`
actions, `base_dir`/`files_base_dir` on `quadlets` and `apps` actions, `home`
on `users` actions, and `path` on `samba` and `nfs` actions, which may only
be left out or set to the default (`/etc/samba/smb.conf`, `/etc/exports`).
So is `run_as` on any module's action, unless it is `"user"` or `"apps"`
(the signed-in user's own view, or that of the `ultramarine-apps` account
user apps run under): running a read as root shows the host's view (rootful
containers and their environment, every VM). So is `show_env: true` on
`podman.inspect`, which would show the apps' secrets. Otherwise the request
is `forbidden`. The setup session and granted users
always get the default directories; remote controllers may set them. Stored grants that are
no longer grantable (such as `files: view` from an earlier release) are
ignored. Grants stored under the page's earlier name, `services`, are read as
`system_services`.

Managing users, reading or writing files (the files module runs as root on
any path), settings or storage (mounting is root-equivalent), and
anything that manages rootful systemd units, containers or VMs, is never
grantable. App management (`apps.create/update/remove`,
`quadlets.write/delete/install`) stays administrator-only even though apps
now run rootless under `ultramarine-apps` by default: its payloads can read
recipes from host paths and relabel paths as root (`selinux`), system scope
is still rootful, and every app shares the one account, so one app's units
could read another's secrets.

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
  `/run/issue.d/50-tetra-setup.issue` (getty login banner, mode `0600`, read by agetty as root). It is never shown
  over SSH.
- The code stays the same across reboots until setup completes or the
  wrong-code limit replaces it. Tetra republishes a replaced code itself.
- `sudo tetra setup code` prints the current code (and, like `--publish`,
  writes it to the console, so the printed code is always the one shown).
  Publishing only creates the files; `/run/tetra` keeps the socket unit's
  `0755` mode so the OOBE can reach the socket.
- `sudo tetra setup code` prints the code and, once Caddy has created its
  internal CA, a second line `CA SHA-256 AA:BB:…` with the fingerprint of the
  CA's root certificate, which the console screen shows so people can check
  the certificate warning the OOBE gets. `--json` prints
  `{"code": ..., "ca_fingerprint": ... | null}` instead. Caddy creates the CA
  the first time it serves the OOBE's site, so right after the first boot the
  fingerprint may still be `null`.
- Publishing also writes the OOBE's Caddy site (see [Caddy](#caddy)), which
  is why `tetra-setup-code.service` runs before `caddy.service`. Once setup
  has completed it leaves the site alone: only the handoff removes it.
- `sudo tetra setup complete` finishes setup from the console, with the same
  check as `setup.complete` (an eligible administrator must exist), then
  starts the dashboard (`--no-block`) and stops the OOBE right away. Use it on
  upgraded hosts and development machines that have no OOBE run.
- The console commands (`tetra setup code`, `complete`, `finish-handoff`)
  take the same `--state-dir` (`TETRA_STATE_DIR`) and `--caddy-sites-dir`
  (`TETRA_CADDY_SITES_DIR`) as `tetra agent-serve`; set them the same way
  when the daemon uses other directories.

## Caddy

Tetra writes its sites to `/etc/caddy/Caddyfile.d/*.caddyfile`. terra-caddy's
default `/etc/caddy/Caddyfile` already ends with
`import Caddyfile.d/*.caddyfile`, so no extra import line is needed; a server
configuration package that ships its own Caddyfile must keep that line.
Files Tetra did not write in that directory are never changed.

| File | Written by |
| --- | --- |
| `00-ultramarine-dashboard.caddyfile` | `access.set` |
| `00-ultramarine-setup.caddyfile` | `tetra setup code` while setup is incomplete; removed by the handoff |
| `<domain>.caddyfile` | `reverse_proxy.write` |

Released versions up to 0.2.3 wrote `reverse_proxy` sites to
`/etc/caddy/tetra-sites/<domain>.caddy`. When `tetra agent-serve` starts it
moves the ones Tetra wrote (starting with `# Managed by Tetra reverse_proxy`)
to `/etc/caddy/Caddyfile.d/<domain>.caddyfile` and reloads Caddy, leaving
other files, and any whose new name is already taken, where they are. An
`import` of the old directory in a Caddyfile can then be removed. They go to
`/etc/caddy/Caddyfile.d`, where `reverse_proxy` keeps its sites, even when
`--caddy-sites-dir` names another directory: that option only moves the
dashboard's and the OOBE's sites.

The OOBE's site serves port 6623 on every address, IPv4 and IPv6, with a
certificate from Caddy's internal CA, and proxies to the OOBE on
`127.0.0.1:6624`:

```caddyfile
https://:6623 {
	tls internal {
		on_demand
	}
	reverse_proxy 127.0.0.1:6624
}
```

The site has no hostname (browsers may use any of the server's addresses), so
certificates are issued on demand; Caddy allows that without an `ask`
endpoint because only the internal CA issues them. It does not `bind`
explicitly: Caddy's default wildcard listener covers IPv4 and IPv6 and still
works on hosts with IPv6 disabled.

This is an accepted setup-only risk: any client that reaches port 6623 can
make Caddy issue and store an internal certificate for whatever SNI name it
sends, without limit. An `ask` endpoint or `permission` module would need the
global options of the main Caddyfile, which Tetra does not own, and the
server's addresses are not known when the site is written at boot (DHCP, or
Wi-Fi joined during setup), so they cannot be listed instead. The cost is
disk and CPU, not impersonation: the certificates and keys stay inside Caddy,
which serves them only on this port; no public CA is involved; and the site
is removed when setup completes.

Caddy's admin API listens on `localhost:2019` by default, where any local
user can read and replace the running configuration (including asking it to
expand `{env.*}` placeholders). The server configuration package should move
it to a Unix socket in a directory only root and `caddy` can reach (the
`admin` global option in `/etc/caddy/Caddyfile`).

## Credentials for other services

The Cloudflare Tunnel token and DNS-01 credentials are sealed with
`systemd-creds` (TPM2 when available, no PCR binding) under their credential
name in `/var/lib/tetra/secrets/<name>.cred`. Each file is an ordinary
encrypted systemd credential. The Tailscale auth key is not stored at all:

- `remote_access.tailscale_up {auth_key, serve?: true, funnel?: false}` writes
  the key to a new file of the call's own in `/run/tetra`
  (`tailscale-auth-key-<pid>-<random>`, created exclusively, root-only
  `0600`) for `tailscale up --auth-key=file:<path>` and deletes it right
  after, whether or not that succeeded. Tetra keeps no copy; tailscaled keeps
  its own node key. It then
  forwards Caddy's HTTPS port (the access port, 443 by default) as raw TCP:
  on the tailnet with `tailscale serve --bg --tcp=<port>
  tcp://127.0.0.1:<port>` (the default), or on the internet with `tailscale
  funnel` instead, only when `funnel: true` is sent (Funnel allows ports 443,
  8443 and 10000). Caddy terminates TLS, so the dashboard, apps, the public
  page and forward-auth work as on the LAN once `access.set` uses the node's
  `*.ts.net` name, which the response returns as `hostname`. Caddy gets that
  name's certificate from tailscaled, which
  `/etc/systemd/system/tailscaled.service.d/50-tetra.conf`
  (`TS_PERMIT_CERT_UID=caddy`) allows; tailscaled is restarted once when that
  drop-in is first installed. The port is read from `access.json` when
  `tailscale_up` runs (also in a dry run); an unreadable file is an error,
  not port 443. If a step fails, the call undoes what it set up (the drop-in
  if it installed it, and tailscaled unless it was enabled or running
  before) and returns the error. Connections forwarded by Tailscale reach
  Caddy from `127.0.0.1`; see [Clients forwarded by Tailscale](#clients-forwarded-by-tailscale).
- `remote_access.cloudflared_set_token {token}` installs
  `/etc/systemd/system/cloudflared.service.d/50-tetra.conf`, which loads the
  sealed token with `LoadCredentialEncrypted=` and points cloudflared's
  `TUNNEL_TOKEN_FILE` at it, then enables and restarts `cloudflared.service`.
- `remote_access.tailscale_disable` resets `tailscale serve`, stops and
  disables tailscaled, and deletes Tetra's drop-in. `cloudflared_disable`
  stops and disables cloudflared and deletes its drop-in and the sealed
  token. Both
  clean up even when `systemctl disable --now` fails (for instance when the
  service is not installed); the failure is listed in `commands`.
- `remote_access.status` returns
  `{tailscale: {enabled, serve, funnel, hostname?}, cloudflared: {enabled}}`.
  `tailscaled.service` and `cloudflared.service` ship disabled.

Credentials are never passed as command-line arguments, so they cannot leak
through error messages, the action log or `ps`.

### Clients forwarded by Tailscale

`tailscale serve` and `tailscale funnel` forward raw TCP from tailscaled to
Caddy on `127.0.0.1`, without the PROXY protocol (which would need a listener
wrapper in terra-caddy's main Caddyfile). So every tailnet and Funnel client
reaches Caddy, and through it the dashboard, as `127.0.0.1`. This is
accepted, and it means:

- Caddy's logs and the `remote_addr` the dashboard passes to Tetra show
  `127.0.0.1`, as do `PAM_RHOST` on `auth.password` and the action log.
- All of these clients share one per-address bucket. With Funnel that is
  everyone on the internet: together they get the 16 pending passkey
  ceremonies one address may have, so on a busy Funnel one visitor's new
  ceremony can replace another's pending one (the shared limit of 4096 is
  unchanged). Anything else that limits by address treats them as one client.
- The setup-code throttle is not affected: the OOBE's port (6623) is never
  forwarded by Tailscale (`access.set` refuses it as the dashboard's port).

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
| `access.json` | Access mode, hostname, port, dashboard upstream, certificate challenge and DNS provider (no credentials) |
| `launcher.json` | Launcher entries and the public page setting |
| `secrets/<name>.cred` | Credentials for other services, each sealed with `systemd-creds` ([details](#credentials-for-other-services)) |
| `updates.json` | Update policy (`automatic` or `notify`) |
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
