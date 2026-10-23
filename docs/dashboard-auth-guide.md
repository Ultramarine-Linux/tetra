# Dashboard Guide: Login and Authorization through Tetra

This guide explains how the dashboard (and the OOBE) should use Tetra for
login, sessions and permissions. The full API reference is
[auth-protocol.md](auth-protocol.md).

The rule: **the dashboard never decides who someone is or what they may do.**
It relays credentials to Tetra, stores the token Tetra returns, and sends that
token with every request. Tetra rejects anything the user is not allowed to
do, so hiding UI is a convenience, not a security boundary.

## 1. Running the dashboard so Tetra recognizes it

- Run the dashboard as a rootful system Quadlet without a user namespace,
  so its processes keep the host UID of the `ultramarine-dashboard` account
  (pass that UID numerically, since names in `User=` resolve inside the image).
- Bind-mount the socket into the container
  (`Volume=/run/tetra/tetra.sock:/run/tetra/tetra.sock`) and add the `tetra`
  group, which owns the socket, by its fixed GID: `GroupAdd=241`.

- The OOBE service runs with `User=ultramarine-oobe` and
  `SupplementaryGroups=tetra`.
- Tetra identifies the client from the socket's peer credentials. A
  connection from any other UID is refused.

## 2. One connection, many users

Keep one (or a small pool of) WebSocket connection(s) to the socket in the
SvelteKit server (with Node's `ws`, `ws+unix:///run/tetra/tetra.sock`). Requests carry
their own token, so one connection serves every browser session. Requests run
concurrently, so match responses by `id`, not by order.

```ts
// Sketch, server-side only.
const pending = new Map<string, (r: Response) => void>();
socket.on("message", (data) => {
  const frame = JSON.parse(data.toString());
  if (frame.type === "hello") { hello = frame; return; }
  if (frame.type === "response") pending.get(frame.id)?.(frame), pending.delete(frame.id);
});

function call(op: string, params: unknown, token?: string): Promise<Response> {
  const id = crypto.randomUUID();
  socket.send(JSON.stringify({ type: "request", id, token, op, params }));
  return new Promise((resolve) => pending.set(id, resolve));
}
```

Never expose the Tetra connection, or tokens, to browser JavaScript. The
browser only gets an opaque cookie.

## 3. Storing the token

- After a successful login, put the Tetra token in an `HttpOnly`, `Secure`,
  `SameSite=Strict` cookie, or keep it in a server-side session keyed by a
  random cookie.
- Do not cache the user's identity or permissions longer than one page load:
  call `session.info` when you need them. Tetra re-checks the account and
  admin status on every request anyway.
- On `unauthenticated`, clear the cookie and send the user to the login page.
  This happens on expiry (1 hour idle, 12 hours total), logout, revocation,
  a second-factor reset from the console, when the account is locked, when
  an administrator sets its password or deletes it (`users.set_password`,
  `users.delete`), or when the user's 33rd session pushes out the least
  recently used one (32 sessions per user).
- On logout, call `session.logout` before clearing the cookie.

## 4. Password login

```text
browser ──username/password──▶ dashboard ──auth.password──▶ Tetra
```

1. Call `auth.password {username, password, remote_addr}`. Set `remote_addr`
   to the browser's address from Caddy's `X-Forwarded-For`.
2. If `status` is `authenticated`, store `token` and you are done.
3. If `status` is `second_factor_required`, keep `pending` server-side (with
   the login form state) and ask for a code. Then call
   `auth.second_factor {pending, code}`, or `{pending, recovery_code}` if the
   user chose "use a recovery code".
4. Show one generic message for `invalid_credentials`. Tetra deliberately does
   not say whether the user exists, the password was wrong or the account is
   locked. For `password_expired`, tell the user to change the password on the
   console or over SSH.
5. If the pending login expires (5 minutes) or the user gets the code wrong 5
   times, the answer is `invalid_credentials`. Restart at the password step.
   After 10 wrong TOTP codes in a row for the account (across logins), Tetra
   answers `rate_limited` with `retry_after` and keeps the pending login;
   show the wait, let the user try again on the same form, and offer the
   recovery-code option, which keeps working.

Do not add your own rate limiting that reveals account state; `pam_faillock`
in Tetra's PAM stack handles lockout. It keeps a dashboard-only tally, so a
lockout here does not affect console or SSH logins, and it does not block
passkey logins. A locked-out user with a passkey can still sign in with it.

## 5. Passkeys

Check `hello.passkeys_available` (or `account.status`) before showing passkey
UI. In IP mode every passkey operation returns `passkeys_unavailable`; show
"passkeys need a domain name" instead.

The browser runs the ceremony; Tetra creates and checks the challenge. The
dashboard only relays JSON. Binary fields (`challenge`, `user.id`, credential
ids) are base64url strings in Tetra's JSON. Decode them before calling
`navigator.credentials`, and encode the results back. A helper such as
`@github/webauthn-json` or SimpleWebAuthn's browser `startRegistration` /
`startAuthentication` does this.

**Login with autofill (primary)**

Passkeys are registered as discoverable credentials, so the login page does
not need a username first:

1. When the login page loads, call
   `auth.passkey_begin {conditional: true, remote_addr}` →
   `{ceremony, options}`. Set `remote_addr` as for `auth.password`; pending
   ceremonies are limited per address. Send only the address Caddy saw (the
   last `X-Forwarded-For` entry Caddy appended), never a value the browser
   can choose, or one client can spread its ceremonies over made-up
   addresses.
2. Browser: give the username field `autocomplete="username webauthn"` and
   call `navigator.credentials.get(options)` (with `mediation:
   "conditional"`, which `options` carries) without awaiting it before the
   form is usable. The browser offers the user's passkeys in the username
   autofill.
3. When it resolves, `auth.passkey_finish {ceremony, credential, remote_addr}`
   → the `authenticated` result. A passkey alone is a full login; no TOTP
   prompt.
4. A "Sign in with a passkey" button can do the same without
   `conditional` (a modal browser prompt). If the user submits the password
   form instead, abort the pending `navigator.credentials.get` call. Begin a
   new ceremony when the old one expires (5 minutes) or is used.

**Login with a username (fallback)**

Some security keys cannot store discoverable credentials; they only work
when Tetra lists them. Offer this after a username is entered, for example
as "Use a security key":

1. `auth.passkey_begin {username, remote_addr}` → `{ceremony, options}`.
2. Browser: `navigator.credentials.get(options)` (modal, no autofill).
3. `auth.passkey_finish` as above.

For a username without passkeys Tetra returns a decoy and the browser finds
no matching key; show the same "no passkey found" message and offer the
password form.

**Registration** (logged-in user, for example under account settings)

Adding or removing a passkey, and starting TOTP enrollment, needs a login
from the last 10 minutes. On `reauth_required`, send the user through the
login form again (same username), then retry the step with the new token.

1. `account.passkey_register_begin {name}` → `{ceremony, options}`. The
   options ask for a discoverable credential (`residentKey: "preferred"`);
   pass them through unchanged.
2. Browser: `navigator.credentials.create(options)`.
3. `account.passkey_register_finish {ceremony, credential}`.

Keep the `ceremony` id server-side with the browser session. It is single-use
and expires after 5 minutes.

## 6. TOTP enrollment

1. `account.totp_begin` → `{enrollment, secret, otpauth_uri}`. Render
   `otpauth_uri` as a QR code in the dashboard (Tetra does not render images)
   and show `secret` for manual entry.
2. Ask for the first code, then call
   `account.totp_confirm {enrollment, code}`.
3. Show the 10 `recovery_codes` once, with a "download" and an "I saved them"
   step. Tetra stores only hashes and cannot show them again.

Use `account.totp_disable {code}` and
`account.recovery_regenerate {code}` for the settings page. Both need a
current code. If a user loses everything, an administrator runs
`sudo tetra auth reset-2fa <user>` on the console.

## 7. Permissions in the UI

- `session.info` returns `permissions`:
  - `{"all": true}` for administrators,
  - `{"launcher": "view", "network": "manage", …}` for everyone else.
    `launcher: view` is the default every user has; it backs the Services
    page (section 8). Systemd units and their logs are the separate
    `system_services` page, which users only have if an administrator
    granted it.
- Show a page when the user has at least `view` on it, and enable mutating
  controls with `manage`.
- Some actions are administrator-only whatever the grants; see the table in
  [auth-protocol.md](auth-protocol.md#authorization).
- Always handle `forbidden` from `module.dispatch`, because the table can
  change and admin status is re-checked on every action.

The grant editor (administrators only):

1. `authz.catalog` lists the pages, their display `label` and which levels
   each can be granted. Offer only those.
2. `admin.grants_get {uid}` shows a user's grants and effective permissions.
3. `admin.grants_set {uid, grants: {"storage": "view", "network": null}}`
   changes them. `null` removes a grant. Changes apply to the user's next
   request.

Other administrator tools: `session.list {uid}`,
`admin.sessions_revoke {uid}` (log a user out everywhere) and
`admin.actions {origin: "remote"}` (remote action log). The action log also
records grant changes, session revocations, `access.set`, `setup.complete`
and launcher changes, next to module actions.

## 8. The Services page (launcher)

The landing page for every user is the list of apps they can open. Build it
from `launcher.list` with the user's token; never from `services.*` (those are
systemd units, and non-administrators normally cannot call them).

- `launcher.list` → `{entries: [{id, name, icon, url}]}`. Tetra has already
  filtered the list for this user, so show all of it. `icon` is `null`, an
  icon name or a `data:image/…` URL. Treat every field as untrusted text when
  rendering, and open `url` as a plain link.
- `launcher.get {id}` → `{entry}` for the edit form or a deep link. An entry
  the user cannot see is `not_found`, the same as a deleted one.
- Administrators also get `visibility`, `public` and `source` on each entry.
  Show the editor only to them and save with
  `launcher.set {id?, entry: {name, icon, url, visibility, public}}` (no `id`
  adds an entry) and `launcher.remove {id}`. `bad_request` carries a message
  you can show next to the form.
- The public page is a separate administrator setting:
  `launcher.public_get` and `launcher.public_set {enabled}`. When enabled,
  everyone (logged in or not) can see the names, icons and URLs of entries
  marked `public` at `https://<dashboard>/public/`. Say so next to the
  switch and the per-entry checkbox.

**Letting users into apps.** When the OIDC provider is about to issue or
refresh tokens for an app, or a Caddy `forward_auth` request reaches the
dashboard, ask Tetra with `launcher.can_access {uid, id}` → `{allowed}` and
refuse unless `allowed` is `true`. `id` is the launcher entry of the app (keep
the mapping from OIDC client or host to entry id in the dashboard). This
operation takes no token, so it also works for token refreshes when the user
has no dashboard session; pass the UID Tetra reported for the user at login
(`session.info`), never one taken from the request. It applies the same rules
as the list, so a user can get into exactly the apps they can see.

## 9. Running module actions

Send `module.dispatch {module, action, payload}` with the user's token. Keep
the existing `dry_run` preview flow from [agent-protocol.md](agent-protocol.md).
The result is the action's payload. A failed action returns `action_failed`
with the module's error text, and a full queue returns `queue_full` (retry
with backoff). Module actions run one at a time, so a slow one (an image pull
in `systemctl start`, say) delays the others; host commands are killed after
15 minutes.

Some payload fields are administrator-only (`base_dir`, `files_base_dir`,
`config_dir`, `users.home`, and a non-default `path` on `samba`/`nfs`); a user
who sends one gets `forbidden`, so leave them out of forms for everyone else.
`apps.get` shows secret parameter values as `"********"`; sending that value
back in `apps.update` keeps the stored secret.

The Unix socket and the loopback-only development TCP listener use the same
Tetra-issued session tokens and per-request authorization. Privileged actions
are authorized from the user's admin status and grants. `sudo` in the web
shell (section 10) still asks for the system password separately.

## 10. Web shell

The terminal page gives a signed-in user a shell on the host, as
themselves. The dashboard does not start it and must not try to: it runs in
a container without access to host processes. Tetra opens the PTY and runs
the user's login shell; the dashboard pipes bytes between the browser's
WebSocket and a second connection to Tetra's socket. Nothing else listens.

```text
browser (xterm.js) ⇄ dashboard WebSocket ⇄ dashboard server ⇄ /run/tetra/tetra.sock ⇄ Tetra ⇄ PTY ⇄ shell
```

1. When the user opens the terminal page, call `shell.ticket` with their
   token on your normal connection → `{ticket, expires_at}`. The ticket is
   for that user only, works once, and expires after 30 seconds, so ask for
   it right before step 2 and never send it to the browser.
2. Open a **new** WebSocket to the same socket
   (`ws+unix:///run/tetra/tetra.sock`), one per terminal, wait for `hello`,
   and send `shell.open` as its first request:

   ```ts
   const shell = new WebSocket("ws+unix:///run/tetra/tetra.sock");
   shell.binaryType = "nodebuffer";
   shell.once("message", () => { // hello
     shell.send(JSON.stringify({
       type: "request", id: crypto.randomUUID(), op: "shell.open",
       params: { ticket, cols: term.cols, rows: term.rows },
     }));
   });
   ```

3. The next message is the `response`. If `ok` is `false`, Tetra closes the
   connection: on `invalid_credentials` (the ticket expired or was used) get
   a new ticket and try once more; on `unauthenticated` send the user to the
   login page; on `limit_reached` say they have too many terminals open (4
   per user, 16 on the server); otherwise show the message. If `ok` is
   `true`, the connection is now the terminal:
   - Browser → dashboard → Tetra: send what xterm.js gives you (`onData`,
     encoded as UTF-8; `onBinary` as is) as **binary** messages, at most
     1 MiB each (split larger pastes). Send
     `{"type": "resize", "cols": …, "rows": …}` as a **text** message when the
     terminal's size changes (xterm.js `onResize`).
   - Tetra → dashboard → browser: write **binary** messages to the terminal
     unchanged. A **text** message is `{"type": "exit", "status", "reason"}`:
     show "session ended" (`exited`, with `status`), "you were logged out"
     (`session_ended`), "closed after 30 minutes without input"
     (`idle_timeout`; any input counts, not output) or "closed after
     4 hours" (`max_lifetime`). Tetra closes the connection right after it.
4. Pipe both ways without buffering more than a few messages: when the
   browser is slow, stop reading from Tetra (back-pressure keeps the shell
   waiting instead of filling memory). When the browser's WebSocket closes,
   close the Tetra connection: that ends the shell. Close it, too, when the
   user's dashboard session ends; Tetra also ends the shell by itself within
   5 seconds of a logout, revocation or expiry.

Never reuse a shell connection for requests, and never send `shell.open` on
the shared request connection (`bad_request`). The `result` of `shell.open`
has the `uid`, `username` and transient `unit` of the shell, and its
`idle_timeout` and `max_lifetime` in seconds, for display. Any input
(binary message or valid `resize`) resets the idle timer and keeps the
user's session from expiring for inactivity; that includes what xterm.js
sends by itself, such as mouse and focus reports. Never send input the user
did not cause (keep-alives), or idle shells never end before
`max_lifetime`. Opening and closing shells are
recorded in the action log (module `shell`). Every signed-in user may open a
shell; the setup session and the OOBE may not.

## 11. OOBE flow

The OOBE runs unprivileged as `ultramarine-oobe` on `127.0.0.1:6624`. Tetra
puts it behind Caddy on port 6623 of every address (IPv4 and IPv6) with a
certificate from Caddy's internal CA, so browsers show a certificate warning;
the console shows the CA's SHA-256 fingerprint (`tetra setup code`) next to
the setup code so people can compare it. Every host change goes through Tetra
with the setup session.

1. Connect as `ultramarine-oobe`. `hello.setup_required` tells you whether
   setup is still open.
2. Ask the user for the setup code shown on the server's console and call
   `setup.redeem {code, remote_addr}`, with the browser's address as Caddy
   reported it (the last `X-Forwarded-For` entry). Handle `rate_limited` by
   showing `retry_after`: one address is slowed down after 3 wrong codes, and
   all addresses after 3 wrong codes in total.
3. With the setup token, through `module.dispatch`:
   - keyboard, language and time zone: `settings.set_keymap {layout, variant?}`,
     `settings.set_locale {locale}`, `settings.set_timezone {timezone}`;
   - if `admin_exists` is `false`, create the first administrator:
     `users.create {name}`, `users.set_password {name, password_hash}`, then
     `users.add_admin {name}` (adds `ultramarine-admin`; refused once an
     administrator exists). Optionally `users.set_authorized_keys {name, keys}`
     to install SSH keys. The setup session may only set the password and keys
     of accounts it created itself, and only make those administrators (never
     `root`, an existing administrator or any other existing account), and may
     not pass `home` to `users.create`;
   - hostname (`settings.set_hostname`) and network: `network.interfaces` and
     `network.status` to show the current state; for Wi-Fi,
     `network.scan_wifi {interface}` and `network.connect_wifi {interface,
     ssid, security: {type: "open" | "wpa-personal" | "wpa-enterprise", ...}}`
     (it fails, leaving the old network in place, if the network does not come
     up); for Ethernet, `network.configure`
     (optionally with `wired_8021x: {eap, identity, password?, ca_cert?,
     client_cert?, private_key?, private_key_password?, domain_suffix_match?,
     phase2?}`, certificates and keys as PEM contents or paths; Wi-Fi
     Enterprise takes the same fields) and
     `network.confirm` once the new settings work. A change often drops the
     OOBE's connection; after reconnecting, `network.pending` returns the
     change still awaiting confirmation (with its `confirmation_token`), if
     any, also after a Tetra restart. An unconfirmed change is rolled back
     after 60 seconds by NetworkManager itself (a checkpoint), so the old
     network comes back even if Tetra restarted meanwhile. The `keyfile` in
     the response has 802.1X passwords redacted;
   - updates: `updates.set_policy {policy: "automatic" | "notify"}`. Tetra
     knows whether the host is bootc or package-based and picks the timer;
   - remote access, if wanted: `remote_access.tailscale_up {auth_key, serve,
     funnel}` (serve defaults to `true`, funnel to `false`; it returns the
     node's `*.ts.net` `hostname`, which goes to `access.set` so the dashboard
     works over the tailnet) and
     `remote_access.cloudflared_set_token {token}`. Tetra seals the tunnel
     token and does not keep the Tailscale auth key at all (tailscaled keeps
     its own node key); drop both from the OOBE's memory and state once sent.
     `remote_access.status` shows what is on. Tailscale forwards the
     dashboard's port as it is when `tailscale_up` runs (443 unless
     `access.set` set another), and while Tailscale is set up `access.set`
     refuses to change the port (`conflict`) until
     `remote_access.tailscale_disable`. So for a port other than 443, pass it
     to `access.set` before `tailscale_up`, and keep it when setting the
     `*.ts.net` hostname;
   - `power.reboot` and `power.poweroff` answer first and act 3 seconds later.
4. Set the access mode with `access.set {mode, hostname, port?}` (`port`
   may not be 0, 80, 2019, 6623, 6624 or the dashboard's own port, 3972 by
   default); in domain
   mode add `challenge: "http-01"`, or `challenge: "dns-01"` with
   `dns_provider` and `dns_credentials` (keys as in the caddy-dns module's
   config, listed in [auth-protocol.md](auth-protocol.md#access-and-setup-completion)).
   Tetra writes the dashboard's Caddy site, hands DNS credentials to Caddy
   without writing them into any Caddyfile, writes the dashboard's `ORIGIN`
   and returns `dashboard_url`. A `bad_request` (for example credentials that
   do not match the provider) changes nothing; a failed Caddy reload or
   `ORIGIN` update is reported in `caddy.error` or `dashboard_env.error` of a
   successful result, so check those.
5. Call `setup.complete`. This fails with `setup_incomplete` until an eligible
   administrator exists. On success the setup code no longer works, setup
   sessions end, the console stops showing the code, and Tetra starts the
   dashboard without waiting for it (its first start may pull the image and
   take minutes). The result is `{complete, dashboard_url, handoff_in_seconds,
   handoff}`: show a final screen pointing at `dashboard_url`, because Tetra
   stops and disables the OOBE (and removes its Caddy site) after
   `handoff_in_seconds`, and tell the user the dashboard may need a moment to
   come up.

The setup session is limited to these actions and to the operations
`session.info`, `session.logout`, `setup.status`, `setup.complete`,
`access.get`, `access.set` and `module.dispatch`; anything else returns
`forbidden`, including `services.*`, `network.set_config` and `users.update`.
To support another OOBE step, add its actions one by one to `SETUP_ALLOWED` in
`src/auth/authz.rs`.
