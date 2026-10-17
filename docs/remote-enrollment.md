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
- Choose a validity period that matches the renewal story (see open questions
  below). Tetra does not renew certificates yet.

## WSS endpoint

The endpoint at `control_plane_url` must:

1. Require a client certificate during the TLS handshake and verify it
   against the client CA only (not public roots).
2. Map the verified certificate (serial or SPKI fingerprint) to exactly one
   host record, and refuse revoked or unknown certificates.
3. Check that the `host_id` in the first `hello` frame matches the host the
   certificate maps to, and close the connection otherwise.

The frame protocol after the handshake is unchanged; see
[agent-protocol.md](agent-protocol.md).

## Unenrollment and revocation

`tetra unenroll` is local. It deletes the key, certificate, server CA and
controller record, and makes the running agent drop its session. It does not
call the controller. The controller should:

- let an administrator remove a host, which revokes its certificate so the
  WSS endpoint refuses it, and
- treat a host that re-enrolls as a new CSR. A new key and certificate are
  issued every time.

Turning `remote.enabled` off on the host keeps the enrollment and only stops
connecting, so the controller will see the host go offline rather than
disappear.

## Open questions

- **Renewal.** There is no renewal yet. Options: a `renew` frame over the
  existing mTLS session carrying a new CSR, or re-running `tetra enroll` after
  `tetra unenroll`. Until this exists, certificates need a validity long enough
  to cover the host's life, or an operator has to re-enroll.
- **Unenroll notification.** A future `DELETE` endpoint, authenticated with
  the client certificate, would let `tetra unenroll` revoke the certificate
  itself.
