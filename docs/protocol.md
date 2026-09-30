# Agent ↔ server protocol (v1)

The wire contract between the desktop agent and the `kukux/digital-signature`
package. It implements [desktop-agent-plan.md §8](../desktop-agent-plan.md#8--protocol-pairing-and-signing-jobs)
and fixes the details the plan leaves open. The package's Laravel
implementation (plan phases 3–4) must match this document. It is the server
side of the agent's integration tests; [test/support/mock-server.ts](../test/support/mock-server.ts)
is a runnable reference that performs every check listed here.

## Conventions

- All endpoints live under `<origin>/signature/agent`, over HTTPS, as JSON.
- Binary values: SPKI public keys and signatures are standard **base64**.
  Nonces and tokens are **base64url without padding** (32 random bytes → 43 characters).
- Hashes are lowercase hex SHA-256.
- Every request carries `X-Agent-Version: <semver>`. If it is older than
  `signature.devices.agent.min_version`, respond **426** with
  `{"error":{"code":"agent_outdated","message":"…"},"min_version":"1.0.0"}`.
- Errors: `{"error":{"code":"<snake_case>","message":"<human text>"}}` with a
  4xx status. The agent shows `message` to the user.
- The agent refuses redirects, so don't redirect these routes (for example to a login page).

## Canonical proof message

```
v1|<purpose>|<nonce_b64url>|<user_id>|<payload_hash_hex>
```

This is the same format as the browser device plan, so one verifier serves
both. Purposes used by the agent:

| Purpose | Signed with | `payload_hash` |
|---|---|---|
| `register_agent` | identity key | `sha256(identity_spki_der ‖ session_spki_der)` (binds both keys) |
| `sign_receipt` | identity key | the job's `payload_hash` (the document hash) |
| `request` | session key | `sha256("<METHOD>|<path+query>|<raw body>|<timestamp>")` |

Signatures are **ES256 as ASN.1 DER** (every platform converts, so the server
never sees raw `r‖s`) or **RS256 PKCS#1 v1.5** (Windows Hello). Both verify
with `openssl_verify($message, $sig, $pem, OPENSSL_ALGO_SHA256)`. Session keys
are always ES256. Shared vectors: [test/fixtures/canonical-vectors.json](../test/fixtures/canonical-vectors.json).

## Pairing

### 1. Web: start (session-authenticated, not called by the agent)

The Filament action creates a pairing: `uuid`, `user_id`, an 8-character
`user_code` from `ABCDEFGHJKMNPQRSTUVWXYZ23456789` shown as `XXXX-XXXX` (store
only its hash), a `nonce`, `status = pending`, and `expires_at = now + pairing_ttl`.
Show the code, the origin, and a QR / link:

```
kukuxsign://pair?o=<urlencoded origin>&c=<user_code>
```

A pair link only prefills the agent's pairing form. The user still sees the
origin and clicks Pair.

### 2. `POST /pairings/lookup`: agent looks up the code

```json
{ "user_code": "K7QM-2XPD" }
```

→ 200

```json
{
  "pairing": "<uuid>",
  "nonce": "<b64url>",
  "user_id": "42",
  "user_name": "Juan dela Cruz",
  "server": { "id": "<server id>", "name": "<app name>", "origin": "https://…", "salt": "<per-server salt>" },
  "require_presence": true,
  "expires_at": "<ISO 8601>"
}
```

- 404 `invalid_code` if the code is unknown, used or expired. Throttle this route hard.
- `server.id` must match `[A-Za-z0-9_-]{1,64}` and stay stable: it's the `s=` in job links.
- `server.origin` must equal the origin the agent called. The agent aborts otherwise.
- `server.salt` is used for `hardware_id_hash` and must stay stable per installation.

### 3. `POST /pairings/{pairing}/claim`: agent registers its keys

```json
{
  "user_code": "K7QM-2XPD",
  "algorithm": "ES256",
  "identity_public_key": "<base64 SPKI DER>",
  "session_public_key": "<base64 SPKI DER, ES256>",
  "protection": "secure_enclave",
  "user_presence": true,
  "attestation": null,
  "device": {
    "platform": "macos", "os_version": "15.1.0", "model": "MacBook Pro",
    "model_identifier": "Mac15,3", "form_factor": "laptop",
    "label": "Juan’s MacBook Pro", "hardware_id_hash": "<hex>"
  },
  "agent_version": "1.0.0",
  "proof": "<base64 signature of v1|register_agent|nonce|user_id|sha256(identity‖session)>"
}
```

Server checks, in order: the pairing is `pending` and unexpired; the code
matches; the algorithm is `ES256` or `RS256`; the proof verifies against
`identity_public_key`; if `require_presence`, `user_presence` is true (else 422
`presence_required`). Then set `status = awaiting_confirmation`, store the
payload, and return:

```json
{ "status": "awaiting_confirmation", "poll_secret": "<b64url>" }
```

`attestation`, when present: `{ "format": "windows-hello-tpm", "statement": "<base64>", "chain": ["<base64>"] }`.
Verify it against the Microsoft TPM roots in phase 5 and set `attested`. A
failed check is not fatal.

### 4. Web: confirm (session-authenticated)

The web page shows *"Pair Juan’s MacBook Pro (macOS 15, Secure Enclave)?"*.
Confirm creates the `digital_signature_devices` row (`kind = agent`, plus the
columns in plan §9.1) and fires the new-device notification.

### 5. `POST /pairings/{pairing}/poll`: agent waits for confirmation

```json
{ "poll_secret": "<from claim>" }
```

→ `{"status":"awaiting_confirmation"}`, `{"status":"rejected"}`, `{"status":"expired"}`, or, **once**:

```json
{ "status": "confirmed", "device": { "uuid": "<device uuid>", "label": "…" }, "token": "<agent token>" }
```

Store only `sha256(token)`, scoped to the device. After it's issued, later
polls return 409 `token_already_issued`. The agent polls every 2 s.

## Authenticated agent requests

Every call below sends:

```
Authorization: Bearer <agent token>
X-Agent-Timestamp: <unix seconds>
X-Agent-Nonce: <b64url, ≥ 16 random bytes>
X-Agent-Proof: <base64 ES256 DER signature by the session key of
                v1|request|<nonce>|<user_id>|sha256("<METHOD>|<path+query>|<raw body>|<timestamp>")>
```

`AuthenticateAgent` returns 401 if the token is unknown or revoked, if the
timestamp is more than ±60 s off, if `(device, nonce)` has been seen before
(cache it for at least 120 s), or if the proof doesn't verify against the
device's `session_public_key`. On 401 the agent forgets the pairing and
deletes its keys.

### `GET /status`

→ `{ "device": { "uuid", "label", "status" }, "user": { "id", "name" } }`

### `DELETE /device`

Revokes the device and its tokens (the agent's Unpair). → 204.

## Signing jobs

### Web: create (session-authenticated)

`POST /signature/agent/jobs { purpose: "sign_receipt", signable, document_hash }`
creates a job with a `nonce`, `payload_hash = document_hash`, a one-time
`link_token` (store `sha256`), and `expires_at = now + job_ttl`. The browser
then navigates to:

```
kukuxsign://job/<job uuid>?t=<link_token>&s=<server id>
```

The agent drops any link that doesn't match this shape exactly.

### `POST /jobs/{job}/claim`: agent fetches the job

```json
{ "link_token": "<from the link>" }
```

The job must be `pending`, unexpired, belong to the device's user, and match
the token hash. Then set `status = claimed`, `device_id = this device`, and
**invalidate the link token**. A second claim returns 409 `job_unavailable`.
→ 200:

```json
{
  "uuid": "<job uuid>", "purpose": "sign_receipt", "status": "claimed",
  "nonce": "<b64url>", "user_id": "42", "payload_hash": "<hex>",
  "document": { "title": "Accomplishment Report – Sept" },
  "signer": { "name": "Juan dela Cruz" },
  "expires_at": "<ISO 8601>"
}
```

This is a `POST`, not the plan's `GET ?t=…`: claiming changes state, and the
token stays out of access logs.

The agent refuses a job whose `user_id` differs from the paired user, or
whose `purpose` is not `sign_receipt`.

### `POST /jobs/{job}/complete`

```json
{ "proof": "<base64 identity-key signature of v1|sign_receipt|nonce|user_id|payload_hash>" }
```

The job must be `claimed` by this device, and the proof must verify with the
device's identity key and algorithm. Then set `status = completed`, set
`device_id` on the Signature, write the audit row, and fire `AgentJobUpdated`.
→ `{"status":"completed"}`.

### `POST /jobs/{job}/reject`

```json
{ "reason": "declined" | "os_prompt_cancelled" | "invalid_job" }
```

→ `{"status":"rejected"}`. The web shows *"Declined on your computer"*.
