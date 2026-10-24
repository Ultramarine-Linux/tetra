# Remote Enrollment: Controller Changes

`tetra enroll` now enrolls a host for **outbound** remote control only. The
host no longer registers an inbound `wss://host:7780` address, no longer writes
`TETRA_LISTEN`, and no longer sends a self-signed server certificate. Instead it
sends a certificate signing request (CSR), and the controller returns a client
certificate that the host presents over mTLS when it dials out.

This document describes what the controller (the service behind
`--dashboard-url`) has to change to match. Nothing here has been implemented
on the controller side yet.

## Summary of changes

| Area                       | Before                                          | Now                                                                  |
| -------------------------- | ----------------------------------------------- | -------------------------------------------------------------------- |
| Create request             | `agent_url`, `host_public_key`, `tls_ca_certificate` | `enrollment_version: 2`, `csr`                                       |
| Approval response          | `controller_public_key`                         | `host_id`, `control_plane_url`, `client_certificate`, `server_ca_certificate` |
| Who connects               | Controller dials `agent_url`                    | Host dials `control_plane_url`                                       |
| Host transport identity    | Self-signed server certificate                  | Client certificate signed by the controller's client CA (`clientAuth`) |
| Controller identity on host | Ed25519 controller key written into the local-socket key file | Server CA bundle stored in the enrollment directory                   |

The old flow also wrote the controller's Ed25519 public key into
`/var/lib/tetra/identity/controller-ed25519-public.key`. That is the file the
local Unix socket uses to authenticate the local dashboard, so remote
enrollment was overwriting the local dashboard's key. The new flow does not
touch that file, and the controller should stop returning
`controller_public_key`. Tetra ignores it if present.

## Endpoints

The paths are unchanged. Both requests are JSON over HTTPS. Tetra refuses a
plain `http://` controller URL unless run with `--insecure`, because the server
CA in the approval response is trusted on the strength of that connection.

### `POST /api/tetra/device`

Request:

```json
{
  "enrollment_version": 2,
  "display_name": "host-01",
  "hostname": "host-01.example.com",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"
}
```

- `enrollment_version`: `2` for this flow. A controller that supports both
  flows can switch on this field. Requests without it come from older Tetra
  builds and carry `agent_url` instead of `csr`.
- `csr`: PEM PKCS#10 request. The key is ECDSA P-256. The request asks for
  key usage `digitalSignature` and extended key usage `clientAuth` only. The
  subject CN is the host name, for display only.

Response (unchanged):

```json
{
  "device_code": "opaque, secret to the host",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://control.example.com/tetra/device",
  "expires_in": 600,
  "interval": 5
}
```

The controller should verify the CSR signature here and reject requests whose
key type it will not sign, so the host fails before an administrator approves
anything.

### `PUT /api/tetra/device`

Request (unchanged): `{ "device_code": "..." }`.

Responses:

- `{ "status": "authorization_pending" }`
- `{ "status": "access_denied" }`
- `{ "status": "expired_token" }`
- On approval:

```json
{
  "status": "approved",
  "host_id": "host-01",
  "control_plane_url": "wss://control.example.com/tetra/agent",
  "client_certificate": "-----BEGIN CERTIFICATE-----\n...leaf...\n-----END CERTIFICATE-----\n",
  "server_ca_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

- `host_id`: stable id for this host. Tetra sends it in the `hello` frame.
- `control_plane_url`: must be `wss://`. Tetra rejects anything else.
- `client_certificate`: PEM, leaf first, optionally followed by
  intermediates.
- `server_ca_certificate`: PEM bundle that verifies the certificate served at
  `control_plane_url`. It may be a private CA or the public chain root.

Tetra rejects the approval, and stores nothing, unless the leaf certificate's
public key matches the CSR key, its extended key usage includes `clientAuth`,
and it is currently valid. The approval should be returned once. Later polls
with the same `device_code` should return `expired_token`.

## Signing rules

The controller signs the CSR with a dedicated **client CA**. That CA is used
for nothing else, and is not the CA that issues the controller's own server
certificate.

- Take only the public key from the CSR. Do not copy the requested subject or
  extensions.
- Set extended key usage to `clientAuth` only, key usage to
  `digitalSignature`, and basic constraints to `CA:FALSE`.
- Bind the certificate to the host. For example, set the subject CN to
  `host_id`, or add a `URI` SAN such as `urn:ultramarine:tetra:host:<host_id>`.
  Record the serial number and SPKI fingerprint against the host.
- Choose a validity period with renewal in mind. Tetra renews at two-thirds
  of the lifetime (see [Certificate renewal](#certificate-renewal)), so
  90 days gives a 30-day window to fix a broken renewal before the host drops
  off.

## WSS endpoint

The endpoint at `control_plane_url` must:

1. Require a client certificate during the TLS handshake and verify it
   against the client CA only (not public roots).
2. Map the verified certificate (serial or SPKI fingerprint) to exactly one
   host record, and refuse revoked or unknown certificates.
3. Check that the `host_id` in the first `hello` frame matches the host the
   certificate maps to, and close the connection otherwise.

The frame protocol after the handshake is described in
[agent-protocol.md](agent-protocol.md). Hosts that renew certificates send
`protocol_version` `2026-10-18` or later in `hello`.

## Certificate renewal

The host renews its client certificate over the existing mTLS session, with
no administrator involved. The controller authorizes a renewal by the
certificate the session was opened with: a host may only renew its own
certificate.

### When the host renews

At two-thirds of the current certificate's lifetime (`notBefore` plus
two-thirds of `notAfter - notBefore`), the host generates a new ECDSA P-256
key and sends a CSR for it. If a host connects after that point, it renews
right after `hello`. After a failed attempt it waits a tenth of the remaining
lifetime, at least one minute and at most one hour, before trying again, even
across reconnects.

### Frames

Host to controller:

```json
{
  "type": "renew",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"
}
```

The CSR has the same shape as the enrollment CSR: a new key (never the
current one), key usage `digitalSignature`, extended key usage `clientAuth`.
The host has at most one renewal in flight per session.

Controller to host, on success:

```json
{
  "type": "renewed",
  "client_certificate": "-----BEGIN CERTIFICATE-----\n...leaf...\n-----END CERTIFICATE-----\n"
}
```

On failure:

```json
{ "type": "renew_failed", "error": "human-readable reason" }
```

If the controller does not answer within five minutes, the host treats the
attempt as failed. A controller that does not support renewal should answer
`renew_failed` rather than close the connection.

### Controller rules

1. Verify the CSR signature, and refuse a CSR whose public key equals the
   current certificate's key.
2. Sign it with the client CA under the same [signing rules](#signing-rules)
   as enrollment, bound to the `host_id` of the certificate that opened the
   session. Never take the identity from the CSR.
3. Record the new serial and SPKI fingerprint against the host **before**
   sending `renewed`. The host reconnects with the new certificate right away,
   and the WSS endpoint has to accept it.
4. Keep the old certificate valid. The host goes back to it if the new one is
   refused, so revoking it on issue can strand the host. Revoke the old
   certificate once the host has completed a handshake with the new one, or
   let it expire.

Renewal does not change the server CA. Rotating `server_ca_certificate` still
needs a re-enrollment.

### What the host does with the answer

The host checks that the returned leaf is for the key it just generated,
allows `clientAuth`, and is currently valid. If any check fails, nothing is
written and the attempt counts as failed. Otherwise it:

1. writes the new certificate and key next to the current ones as
   `client.crt.next` and `client.key.next`,
2. closes the session and reconnects with the new pair,
3. if the WebSocket upgrade succeeds, renames the new files over
   `client.crt` and `client.key` and carries on with that session,
4. if it fails but the old pair still connects, deletes the `.next` files and
   keeps using the old certificate. If neither connects, it keeps both and
   tries the new pair first on the next reconnect.

The renames are ordered so that a crash at any point leaves either the old or
the new pair, never a key that does not match its certificate.

## Unenrollment and revocation

`tetra unenroll` is local. It deletes the key, certificate, server CA and
controller record (and any renewal in progress), and makes the running agent drop its session. It does not
call the controller. The controller should:

- let an administrator remove a host, which revokes its certificate so the
  WSS endpoint refuses it, and
- treat a host that re-enrolls as a new CSR. A new key and certificate are
  issued every time.

Turning `remote.enabled` off on the host keeps the enrollment and only stops
connecting, so the controller will see the host go offline rather than
disappear.

## Open questions

- **Unenroll notification.** A future `DELETE` endpoint, authenticated with
  the client certificate, would let `tetra unenroll` revoke the certificate
  itself.
