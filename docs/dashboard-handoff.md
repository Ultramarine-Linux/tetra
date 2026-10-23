# Dashboard handoff: protocol changes on `cypress/simplification-and-full-pass`

What `Ultramarine-Linux/dashboard` has to change to work with this branch.
Nothing here is implemented in the dashboard repo. The reference docs are
[auth-protocol.md](auth-protocol.md) (operations, errors, permissions),
[dashboard-auth-guide.md](dashboard-auth-guide.md) (flows) and
[agent-protocol.md](agent-protocol.md) (module payloads).

All examples are frames on the local socket (`ws+unix:///run/tetra/tetra.sock`).
Module actions go through `module.dispatch`:

```json
{ "type": "request", "id": "…", "token": "tts_…", "op": "module.dispatch",
  "params": { "module": "apps", "action": "list", "payload": { } } }
```

## 1. `apps.list` scope

User apps now run rootless under the `ultramarine-apps` account. `apps` and
`quadlets` actions take `scope`: `"apps"` (the default) or `"system"`.
`apps.list` also takes `"all"`. The old `"user"` scope is gone and refused.

| `scope` | Lists | Needs |
| --- | --- | --- |
| omitted / `"apps"` | the apps account's apps | `apps: view` |
| `"system"` | rootful system services | `apps: view` and `system_services: view` |
| `"all"` | both | `apps: view` and `system_services: view` |

Any `scope` other than `"apps"` on any `apps` or `quadlets` action needs
`system_services: view`. Administrators always pass.

```json
{ "type": "request", "id": "l1", "token": "tts_…", "op": "module.dispatch",
  "params": { "module": "apps", "action": "list", "payload": { "scope": "all" } } }
```

```json
{ "type": "response", "id": "l1", "ok": true, "result": {
  "apps": [
    { "name": "nextcloud", "scope": "apps", "recipe_id": "nextcloud",
      "recipe_version": "1.2.0", "units": ["nextcloud.container"],
      "services": ["nextcloud.service"], "created_at": 1750000000,
      "updated_at": 1750000000,
      "bundle_dir": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets/nextcloud" }
  ],
  "invalid": [],
  "roots": [
    { "scope": "apps", "files_base_dir": "/var/lib/ultramarine-apps/.local/share/tetra/quadlets" },
    { "scope": "system", "files_base_dir": "/var/lib/tetra/quadlets" }
  ] } }
```

- `roots` is new. `files_base_dir` is only at the top level when a single
  scope is listed.
- Without `system_services`, `"system"` and `"all"` return
  `{"ok": false, "error": {"code": "forbidden", …}}`. Show system-scope apps
  on the system services page, not the apps page.
- Drop the dashboard's `'user'` scope default and the hardcoded
  `/home/a11y` paths (`QuadletEditor.svelte`, `recipes.ts`). Tetra resolves
  paths from the scope.

## 2. Web shell: `shell.ticket` and the terminal stream

Tetra owns the PTY. The dashboard only pipes bytes between the browser and a
second connection to the same socket. There's no new listener.

**a. Get a ticket** on the user's normal request connection. Only dashboard
user sessions can get one; the ticket is single-use and lasts 30 seconds.

```json
{ "type": "request", "id": "t1", "token": "tts_…", "op": "shell.ticket" }
```

```json
{ "type": "response", "id": "t1", "ok": true,
  "result": { "ticket": "…", "expires_at": 1750000030 } }
```

**b. Open a new connection** to the socket, one per terminal. Wait for
`hello`, then send `shell.open` as its first request. It needs no token,
because the ticket is the credential.

```json
{ "type": "request", "id": "sh-1", "op": "shell.open",
  "params": { "ticket": "…", "cols": 120, "rows": 40 } }
```

```json
{ "type": "response", "id": "sh-1", "ok": true,
  "result": { "uid": 1000, "username": "alice",
              "unit": "tetra-shell-1000-1a2b3c4d5e6f.service",
              "cols": 120, "rows": 40,
              "idle_timeout": 1800, "max_lifetime": 14400 } }
```

On an error Tetra sends a normal error response and closes the connection:

| Error code | What the dashboard should do |
| --- | --- |
| `invalid_credentials` | The ticket expired or was used: get a new one and retry once. |
| `unauthenticated` | The session ended: send the user to login. |
| `limit_reached` | Too many shells open (4 per user, 16 on the host). |
| `bad_request`, `forbidden`, `wrong_client`, `internal` | Show the message. |

**c. From then on the connection is the terminal.**

- **Binary messages** carry terminal bytes, both ways. Send xterm.js `onData`
  as UTF-8 and `onBinary` as is, at most 1 MiB per message; split big pastes,
  because a larger message ends the shell with `protocol_error`. Write
  Tetra's binary messages to the terminal unchanged.
- **Text messages** are JSON control frames.
  - Dashboard → Tetra, on resize:
    `{"type": "resize", "cols": 132, "rows": 43}`
  - Tetra → dashboard, once, right before it closes the connection:
    `{"type": "exit", "status": 0, "reason": "exited"}`. `status` is
    `null` unless the shell exited by itself with a status.

| `reason` | Show |
| --- | --- |
| `exited` | "session ended" (with `status`) |
| `session_ended` | "you were logged out" (logout, revocation, expiry, locked account) |
| `idle_timeout` | "closed after 30 minutes without input" (only typing counts) |
| `max_lifetime` | "closed after 4 hours" |
| `protocol_error` | "the terminal sent too much at once" |

- When the browser's WebSocket closes, close the Tetra connection; that ends
  the shell. Tetra also ends it within 5 seconds of a logout, revocation or
  session expiry.
- Apply back-pressure: stop reading from Tetra while the browser is slow.
- Never send other requests on a shell connection, and never send
  `shell.open` on the shared request connection (`bad_request`).

## 3. `source` on catalog installs

`apps.create` and `apps.update`, plus `recipes.render` and
`recipes.render_inline`, take a `source` the dashboard gets from the catalog:

```json
{ "type": "request", "id": "c1", "token": "tts_…", "op": "module.dispatch",
  "params": { "module": "apps", "action": "create", "payload": {
    "name": "nextcloud",
    "recipe": "<exact recipe YAML bytes from the catalog>",
    "templates": { "containers/nextcloud.container.tera": "…" },
    "values": { "domain": "cloud.example.com" },
    "source": {
      "catalog": "official",
      "url": "https://catalog.ultramarine-linux.org/apps/nextcloud/1.2.0",
      "sha256": "9f2c…64 hex…"
    }
  } } }
```

- **`catalog`** is `"official"`, `"community"` or `"custom"`. A missing
  `source` means custom.
- **`sha256`** is the bundle digest of the exact recipe and template bytes, in
  the format defined in [recipes.md](recipes.md#canonical-bundle-digest-v1):
  `tetra-recipe-bundle-v1\0`, the length-prefixed recipe, the template count,
  then the templates in sorted name order, each name and body
  length-prefixed (u64 big-endian). Tetra recomputes it and refuses a
  mismatch with `action_failed` and `recipe source sha256 mismatch`. Take the
  expected digest from the catalog index. The dashboard must not compute it
  from what it downloaded, or the check proves nothing.
- **Images:** official and community recipes must pin every image by digest
  (`Image=…@sha256:<64 hex>`). Only `"custom"` may send
  `"allow_unpinned_images": true`.
- **`url`** is recorded for the audit trail only; Tetra never fetches it.
- **`catalog` is a claim, not a verification.** Tetra checks that the bytes
  match `sha256` and applies the pinning policy for the claimed catalog; it
  cannot know who published them. Don't show an app as "verified" or
  "official" in the UI because of the stored `source.catalog`; that is only
  as trustworthy as the catalog index the dashboard took the digest from.
- **Response:** the manifest records `source` (with the digest Tetra
  computed) and `allow_unpinned_images`.
- **`apps.update`** with a new recipe and no `source` makes the app custom
  again, so an old official claim never carries over to new bytes.

TypeScript sketch of the digest, if the dashboard wants to check a catalog
entry before sending it:

```ts
import { createHash } from "node:crypto";

function u64(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

export function bundleSha256(recipe: string, templates: Record<string, string>): string {
  const h = createHash("sha256");
  h.update("tetra-recipe-bundle-v1\0");
  const r = Buffer.from(recipe, "utf8");
  h.update(u64(r.length)); h.update(r);
  const names = Object.keys(templates).sort((a, b) =>
    Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
  h.update(u64(names.length));
  for (const name of names) {
    const n = Buffer.from(name, "utf8"), body = Buffer.from(templates[name], "utf8");
    h.update(u64(n.length)); h.update(n);
    h.update(u64(body.length)); h.update(body);
  }
  return h.digest("hex");
}
```

## Other changes the dashboard will notice

- **`reauth_required`** (new error code): `account.totp_begin`,
  `account.passkey_register_begin` and `account.passkey_remove` need a login
  from the last 10 minutes. Send the user through login again, then retry.
- **`run_as`** on module payloads: `"user"` (the default for most reads),
  `"apps"` (the default for `podman`), `"root"` or `"both"`. `"root"` and
  `"both"` are admin-only. `"both"` returns
  `{user: {ok, result|error}, root: {ok, result|error}}`.
- **`podman.inspect`** hides container environment values unless an admin
  sends `"show_env": true`.
- **Now admin-only:** `quadlets.read`, `recipes.render_inline`,
  `samba.set_config` and `nfs.set_config`. `samba`/`nfs` `path` may only be
  the default for non-admins.
- **`apps.get`** shows secret parameter values as `"********"`. Send the
  placeholder back unchanged on update and Tetra keeps the stored value.
- **`network.pending`**: after a network change cuts the connection, call it
  on reconnect to get the confirmation token, then `network.confirm`.
  NetworkManager rolls the change back after 60s otherwise.
- **Sessions:**
  - a user can have at most 32 sessions; the 33rd login ends the oldest.
  - `users.set_password` and `users.delete` end the target's other
    sessions.
- **No signatures:** commands are not signed. `module.dispatch` params take
  only `module`, `action` and `payload`, and unknown fields such as
  `signature` are refused (`bad_request`); controller-key login is gone. On
  the remote path an empty `signature` string is refused and any other value
  is ignored. Remote commands ignore `user` and run as root.
