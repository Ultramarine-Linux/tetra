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
  a second-factor reset from the console, or when the account is locked.
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

Do not add your own rate limiting that reveals account state; `pam_faillock`
in Tetra's PAM stack handles lockout.

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

**Login**

1. `auth.passkey_begin {username}` → `{ceremony, options}`. Without a
   username you get a discoverable challenge (pass `conditional: true` for
   autofill UI).
2. Browser: `navigator.credentials.get(options)`.
3. `auth.passkey_finish {ceremony, credential, remote_addr}` → the
   `authenticated` result. A passkey alone is a full login; no TOTP prompt.

**Registration** (logged-in user, for example under account settings)

1. `account.passkey_register_begin {name}` → `{ceremony, options}`.
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
  - `{"services": "view", "network": "manage", …}` for everyone else.
- Show a page when the user has at least `view` on it, and enable mutating
  controls with `manage`.
- Some actions are administrator-only whatever the grants; see the table in
  [auth-protocol.md](auth-protocol.md#authorization).
- Always handle `forbidden` from `module.dispatch`, because the table can
  change and admin status is re-checked on every action.

The grant editor (administrators only):

1. `authz.catalog` lists the pages and which levels each can be granted.
   Offer only those.
2. `admin.grants_get {uid}` shows a user's grants and effective permissions.
3. `admin.grants_set {uid, grants: {"storage": "view", "network": null}}`
   changes them. `null` removes a grant. Changes apply to the user's next
   request.

Other administrator tools: `session.list {uid}`,
`admin.sessions_revoke {uid}` (log a user out everywhere) and
`admin.actions {origin: "remote"}` (remote action log).

## 8. Running module actions

Send `module.dispatch {module, action, payload}` with the user's token. Keep
the existing `dry_run` preview flow from [agent-protocol.md](agent-protocol.md).
The result is the action's payload. A failed action returns `action_failed`
with the module's error text, and a full queue returns `queue_full` (retry
with backoff).

The old flow is gone:

- Ed25519 controller keys and signed commands on the local socket,
- `elevation_request` and the 30-minute password elevation,
- the `user` field in `authenticate`.

Privileged actions are now authorized per request from the user's admin
status and grants. Web shell `sudo` still asks for the system password
separately.

## 9. OOBE flow

1. Connect as `ultramarine-oobe`. `hello.setup_required` tells you whether
   setup is still open.
2. Ask the user for the setup code shown on the server's console and call
   `setup.redeem {code}`. Handle `rate_limited` by showing `retry_after`.
3. With the setup token:
   - if `admin_exists` is `false`, create the first administrator. Call
     `users.create`, then `users.set_password` with a hashed password, then
     `users.update {groups: ["ultramarine-admin"]}`, all through
     `module.dispatch`;
   - set the hostname (`settings.set_hostname`) and network
     (`network.configure`, then `network.confirm` once the new settings work);
   - set the access mode with `access.set {mode, hostname}`. Tetra writes the
     dashboard's Caddy site and reloads Caddy.
4. Call `setup.complete`. This fails with `setup_incomplete` until an eligible
   administrator exists. Afterwards the setup code no longer works, setup
   sessions end, and the console stops showing the code.

The setup session is limited to these operations; anything else returns
`forbidden`. To support another OOBE step (an updates module, for example),
add its actions to `SETUP_ALLOWED` in `src/auth/authz.rs`.
