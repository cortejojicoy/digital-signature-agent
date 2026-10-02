// API reference data for the docs site. One entry per endpoint, function,
// method, type, IPC call or native export. app.mjs renders it; keep it in
// sync with src/ and native/ (each entry links to its source line).

export const REPO = 'https://github.com/cortejojicoy/digital-signature-agent';
export const BRANCH = 'main';

export const sections = [
  // ───────────────────────────── HTTP ─────────────────────────────
  {
    id: 'http',
    title: 'Server HTTP API',
    intro:
      'Endpoints the agent calls under `<origin>/signature/agent`, as JSON. Every request sends `X-Agent-Version`; redirects are refused; ' +
      'errors are `{"error":{"code","message"}}`. Overview: [How the API works](#/how-the-api-works).',
    groups: [
      {
        title: 'Pairing (unauthenticated)',
        items: [
          {
            id: 'post-pairings-lookup',
            kind: 'endpoint',
            method: 'POST',
            path: '/signature/agent/pairings/lookup',
            name: 'Look up a pairing code',
            summary:
              'The agent sends the 8-character code the user typed. The server returns the pairing, its nonce, the user, and a description of itself.',
            auth: 'None. The one-time user code carries the trust, so throttle this route hard.',
            request: `{ "user_code": "K7QM-2XPD" }`,
            response: `{
  "pairing": "<uuid>",
  "nonce": "<b64url>",
  "user_id": "42",
  "user_name": "Juan dela Cruz",
  "server": {
    "id": "<[A-Za-z0-9_-]{1,64}>",
    "name": "<app name>",
    "origin": "https://…",
    "salt": "<per-server salt>"
  },
  "require_presence": true,
  "blocked_device_types": ["virtual_machine"],
  "expires_at": "<ISO 8601>"
}`,
            errors: [{ status: 404, code: 'invalid_code', when: 'The code is unknown, used or expired.' }],
            notes: [
              '`server.origin` must equal the origin the agent called, or the agent aborts with `origin_mismatch`.',
              '`server.id` must stay stable: it is the `s=` parameter in job links.',
              '`server.salt` is used for `hardware_id_hash` and must stay stable per installation.',
              '`blocked_device_types` lets the agent stop before creating keys when its detected type is refused (`device_type_not_allowed`). Older servers omit it; the claim is still checked.',
              'Before creating keys, the agent also stops with `app_already_paired` if this computer already holds a different account’s signature for this server: one signature per app per computer.',
            ],
            client: 'agentapi-lookuppairing',
            source: 'src/main/api.ts#L166',
          },
          {
            id: 'post-pairings-claim',
            kind: 'endpoint',
            method: 'POST',
            path: '/signature/agent/pairings/{pairing}/claim',
            name: 'Claim a pairing (register keys)',
            summary:
              'Registers the identity key and session key. The `register_agent` proof is signed by the identity key, which triggers Touch ID or Windows Hello.',
            auth: 'None. The user code must match, and the proof must verify against `identity_public_key`.',
            request: `{
  "user_code": "K7QM-2XPD",
  "algorithm": "ES256",
  "identity_public_key": "<base64 SPKI DER>",
  "session_public_key": "<base64 SPKI DER, ES256>",
  "protection": "secure_enclave",
  "user_presence": true,
  "attestation": null,
  "device": {
    "platform": "macos",
    "os_version": "15.1.0",
    "model": "MacBook Pro",
    "model_identifier": "Mac15,3",
    "form_factor": "laptop",
    "label": "Juan’s MacBook Pro",
    "hardware_id_hash": "<hex> | null",
    "device_type": "macbook_pro",
    "chassis_type": null,
    "virtual": false
  },
  "agent_version": "1.0.0",
  "proof": "<base64 sig of v1|register_agent|nonce|user_id|sha256(identity‖session)>"
}`,
            response: `{
  "status": "awaiting_confirmation",
  "poll_secret": "<b64url>",
  // this user's device on this computer, which confirming updates; else null
  "existing_device": { "uuid": "…", "label": "Work laptop", "device_type": "macbook_pro" }
}`,
            errors: [
              { status: 422, code: 'presence_required', when: '`require_presence` is set but `user_presence` is false.' },
              { status: 422, code: 'device_type_not_allowed', when: 'The detected `device_type` is in `blocked_device_types`, or `virtual` is true and virtual machines are blocked.' },
              { status: 409, code: 'machine_already_paired', when: 'Another account’s active agent device has the same `hardware_id_hash`. The message never names the owner.' },
              { status: '4xx', code: '…', when: 'The pairing is not pending, it expired, the code doesn’t match, the algorithm isn’t ES256/RS256, or the proof fails.' },
            ],
            notes: [
              'Checks run in this order: pending and unexpired → code → algorithm → proof → presence → device type → one active device per computer.',
              '`hardware_id_hash` is `sha256(server.salt ‖ hardware uuid)`, or `null` when the firmware has no usable uuid (never the hash of an empty string). Without it the server can’t enforce one device per computer.',
              '`device_type` is one of the 22 catalogue values (see `DEVICE_TYPES`); unknown values become `other`. `chassis_type` is the SMBIOS type 3 value on Windows.',
              'When `attestation` is present it looks like `{ "format": "windows-hello-tpm", "statement": "<base64>", "chain": ["<base64>"] }`. A failed attestation check is not fatal.',
            ],
            client: 'agentapi-claimpairing',
            source: 'src/main/api.ts#L170',
          },
          {
            id: 'post-pairings-poll',
            kind: 'endpoint',
            method: 'POST',
            path: '/signature/agent/pairings/{pairing}/poll',
            name: 'Poll for confirmation',
            summary: 'The agent polls every 2 s until the user confirms (or rejects) the pairing on the web.',
            auth: 'The `poll_secret` returned by claim.',
            request: `{ "poll_secret": "<from claim>" }`,
            response: `// one of
{ "status": "awaiting_confirmation" }
{ "status": "rejected" }
{ "status": "expired" }
// …or, exactly once:
{
  "status": "confirmed",
  "device": { "uuid": "<device uuid>", "label": "…", "device_type": "macbook_pro" },
  "token": "<agent token>",
  "rebound": false
}`,
            errors: [{ status: 409, code: 'token_already_issued', when: 'The token was already returned by an earlier poll.' }],
            notes: [
              'The server stores only `sha256(token)`, scoped to the device.',
              '`rebound: true` means the same user re-paired this computer: the existing device (same uuid and history) got the new keys, and its old token was revoked.',
              '`device.device_type` may be the owner’s correction of what the agent detected.',
            ],
            client: 'agentapi-pollpairing',
            source: 'src/main/api.ts#L174',
          },
        ],
      },
      {
        title: 'Authenticated agent calls',
        intro:
          'Each call sends a bearer token plus a request proof signed by the session key (no user prompt). A leaked token alone is useless. ' +
          'On any 401 the agent forgets the pairing and deletes its keys.',
        headers: `Authorization: Bearer <agent token>
X-Agent-Timestamp: <unix seconds>
X-Agent-Nonce: <b64url, ≥ 16 random bytes>
X-Agent-Proof: <base64 ES256 DER signature by the session key of
  v1|request|<nonce>|<user_id>|sha256("<METHOD>|<path+query>|<raw body>|<timestamp>")>`,
        items: [
          {
            id: 'get-status',
            kind: 'endpoint',
            method: 'GET',
            path: '/signature/agent/status',
            name: 'Device status',
            summary: 'Returns the paired device and user, and the account’s other active signing devices.',
            auth: 'Bearer + X-Agent-Proof',
            response: `{
  "device": { "uuid": "…", "label": "…", "status": "…" },
  "user": { "id": "42", "name": "Juan dela Cruz" },
  "other_devices": [
    { "uuid": "…", "label": "Office Mac mini", "device_type": "mac_mini", "last_used_at": "<ISO 8601> | null" }
  ]
}`,
            errors: [{ status: 401, code: '…', when: 'Unknown or revoked token, timestamp more than ±60 s off, replayed nonce, or bad proof.' }],
            client: 'agentapi-status',
            source: 'src/main/api.ts#L180',
          },
          {
            id: 'delete-device',
            kind: 'endpoint',
            method: 'DELETE',
            path: '/signature/agent/device',
            name: 'Unpair (revoke device)',
            summary:
              'Revokes the device and its tokens. Called by the agent’s Unpair button. If it fails (offline), the agent deletes the signing key at once, keeps only the session key, and retries the revoke at start-up, hourly, and before pairing with the same server again.',
            auth: 'Bearer + X-Agent-Proof',
            response: '204 No Content',
            client: 'agentapi-unpair',
            source: 'src/main/api.ts#L198',
          },
          {
            id: 'post-jobs-claim',
            kind: 'endpoint',
            method: 'POST',
            path: '/signature/agent/jobs/{job}/claim',
            name: 'Claim a signing job',
            summary:
              'Consumes the one-time `link_token` from the `kukuxsign://job/…` link and binds the job to this device. The job content comes from the server, never from the link.',
            auth: 'Bearer + X-Agent-Proof',
            request: `{ "link_token": "<from the link>" }`,
            response: `{
  "uuid": "<job uuid>",
  "purpose": "sign_receipt",
  "status": "claimed",
  "nonce": "<b64url>",
  "user_id": "42",
  "payload_hash": "<hex>",
  "document": { "title": "Accomplishment Report – Sept" },
  "signer": { "name": "Juan dela Cruz" },
  "expires_at": "<ISO 8601>"
}`,
            errors: [{ status: 409, code: 'job_unavailable', when: 'The job was already claimed, or isn’t pending.' }],
            notes: [
              'This is a POST rather than `GET ?t=…`, because claiming changes state and the token stays out of access logs.',
              'The agent refuses a job whose `user_id` differs from the paired user or whose `purpose` isn’t `sign_receipt` (see `validateJob`).',
            ],
            client: 'agentapi-claimjob',
            source: 'src/main/api.ts#L185',
          },
          {
            id: 'post-jobs-complete',
            kind: 'endpoint',
            method: 'POST',
            path: '/signature/agent/jobs/{job}/complete',
            name: 'Complete a job',
            summary: 'Submits the identity-key signature of the `sign_receipt` message.',
            auth: 'Bearer + X-Agent-Proof',
            request: `{ "proof": "<base64 identity-key sig of v1|sign_receipt|nonce|user_id|payload_hash>" }`,
            response: `{ "status": "completed" }`,
            notes: ['The job must be `claimed` by this device, and the proof must verify with the device’s identity key and algorithm.'],
            client: 'agentapi-completejob',
            source: 'src/main/api.ts#L189',
          },
          {
            id: 'post-jobs-reject',
            kind: 'endpoint',
            method: 'POST',
            path: '/signature/agent/jobs/{job}/reject',
            name: 'Reject a job',
            summary: 'Tells the web app the job won’t be signed. The web app shows “Declined on your computer”.',
            auth: 'Bearer + X-Agent-Proof',
            request: `{ "reason": "declined" | "os_prompt_cancelled" | "invalid_job" }`,
            response: `{ "status": "rejected" }`,
            client: 'agentapi-rejectjob',
            source: 'src/main/api.ts#L193',
          },
        ],
      },
      {
        title: 'Common errors',
        items: [
          {
            id: 'error-agent-outdated',
            kind: 'error',
            name: '426 agent_outdated',
            summary:
              'Returned by any route when `X-Agent-Version` is older than `signature.devices.agent.min_version`. The agent then checks for an update immediately.',
            response: `{
  "error": { "code": "agent_outdated", "message": "…" },
  "min_version": "1.0.0"
}`,
            source: 'src/main/api.ts#L121',
          },
        ],
      },
    ],
  },

  // ───────────────────────────── Links ─────────────────────────────
  {
    id: 'links',
    title: 'kukuxsign:// links',
    intro:
      'The web app opens the agent through a custom URL scheme. Link parameters are never trusted: anything that doesn’t match exactly is dropped by `parseLink`.',
    groups: [
      {
        title: 'Link shapes',
        items: [
          {
            id: 'link-pair',
            kind: 'link',
            name: 'Pair link',
            signature: 'kukuxsign://pair?o=<urlencoded origin>&c=<user_code>',
            summary: 'Prefills the pairing form. The user still sees the origin and clicks Pair.',
            params: [
              { name: 'o', type: 'origin', desc: 'HTTPS origin; plain `http://` only for local-network hosts in Developer mode. No path, query, credentials or fragment.' },
              { name: 'c', type: 'user code', desc: '8 characters from `ABCDEFGHJKMNPQRSTUVWXYZ23456789`, with or without the dash.' },
            ],
            source: 'src/main/protocol.ts#L63',
          },
          {
            id: 'link-job',
            kind: 'link',
            name: 'Job link',
            signature: 'kukuxsign://job/<job uuid>?t=<link_token>&s=<server id>',
            summary: 'Starts a signing job on an already-paired server. The agent fetches the job itself from the stored origin for `s`.',
            params: [
              { name: '<job uuid>', type: 'uuid', desc: 'Lowercase UUID.' },
              { name: 't', type: 'token', desc: '43 characters: 32 random bytes, base64url, no padding. One-time use.' },
              { name: 's', type: 'server id', desc: '`[A-Za-z0-9_-]{1,64}`: the `server.id` from pairing lookup.' },
            ],
            notes: ['Extra parameters, repeated parameters, a port, credentials or a fragment all make the link invalid.'],
            source: 'src/main/protocol.ts#L54',
          },
        ],
      },
    ],
  },

  // ───────────────────────────── Canonical ─────────────────────────────
  {
    id: 'canonical',
    title: 'Proof messages',
    intro:
      'Every signature covers one canonical string. It must be byte-identical to the PHP builder in the package; ' +
      '`test/fixtures/canonical-vectors.json` is the shared contract. Signatures are ES256 (ASN.1 DER) or RS256 (PKCS#1 v1.5, Windows Hello), and both verify with `openssl_verify($message, $sig, $pem, OPENSSL_ALGO_SHA256)`.',
    format: 'v1|<purpose>|<nonce_b64url>|<user_id>|<payload_hash_hex>',
    purposes: [
      { purpose: 'register_agent', key: 'identity key', hash: 'sha256(identity_spki_der ‖ session_spki_der)' },
      { purpose: 'sign_receipt', key: 'identity key', hash: 'the job’s payload_hash (the document hash)' },
      { purpose: 'request', key: 'session key', hash: 'sha256("<METHOD>|<path+query>|<raw body>|<timestamp>")' },
    ],
    groups: [
      {
        title: 'src/main/canonical.ts',
        items: [
          {
            id: 'canonicalmessage',
            kind: 'function',
            name: 'canonicalMessage',
            signature: 'canonicalMessage(purpose: string, nonce: string, userId: string | number, payloadHash: string): string',
            summary: 'Builds and validates the canonical proof message.',
            params: [
              { name: 'purpose', type: 'string', desc: 'Must match `[a-z_]{1,64}`.' },
              { name: 'nonce', type: 'string', desc: 'base64url, 1–128 characters.' },
              { name: 'userId', type: 'string | number', desc: 'Non-empty, at most 64 characters, no `|` or whitespace.' },
              { name: 'payloadHash', type: 'string', desc: '64 lowercase hex characters (SHA-256).' },
            ],
            returns: '`"v1|<purpose>|<nonce>|<userId>|<payloadHash>"`',
            throws: '`CanonicalError` if any part fails validation.',
            example: `canonicalMessage('sign_receipt', 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', 42,
  '43cc23fa52b87b4cc1d02b5b114154151d6adddb17c9fddc06b027fa99e24008');
// → 'v1|sign_receipt|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8|42|43cc23fa…4008'`,
            source: 'src/main/canonical.ts#L17',
          },
          {
            id: 'sha256hex',
            kind: 'function',
            name: 'sha256Hex',
            signature: 'sha256Hex(data: string | Buffer): string',
            summary: 'Lowercase hex SHA-256.',
            source: 'src/main/canonical.ts#L26',
          },
          {
            id: 'registrationpayloadhash',
            kind: 'function',
            name: 'registrationPayloadHash',
            signature: 'registrationPayloadHash(identitySpki: Buffer, sessionSpki: Buffer): string',
            summary: 'Payload hash for `register_agent`: `sha256(identity ‖ session)`, which binds both public keys to the pairing.',
            source: 'src/main/canonical.ts#L31',
          },
          {
            id: 'requestpayloadhash',
            kind: 'function',
            name: 'requestPayloadHash',
            signature: 'requestPayloadHash(method: string, path: string, body: string, timestamp: string | number): string',
            summary: 'Payload hash for `request` proofs on authenticated calls.',
            params: [
              { name: 'method', type: 'string', desc: 'Upper-cased before hashing.' },
              { name: 'path', type: 'string', desc: 'Path including the query string.' },
              { name: 'body', type: 'string', desc: 'The exact bytes sent (`""` for GET).' },
              { name: 'timestamp', type: 'string | number', desc: 'Unix seconds, the same value sent in `X-Agent-Timestamp`.' },
            ],
            example: `requestPayloadHash('GET', '/signature/agent/status', '', '1767225600');
// hashes "GET|/signature/agent/status||1767225600"
// → '16f55ff9363fd17f8d2bcdad0952f4d34355e0d7336881bad9b44bcccea375dc'`,
            source: 'src/main/canonical.ts#L39',
          },
          {
            id: 'canonicalerror',
            kind: 'class',
            name: 'CanonicalError',
            signature: 'class CanonicalError extends Error',
            summary: 'Thrown by `canonicalMessage` on invalid input.',
            source: 'src/main/canonical.ts#L15',
          },
        ],
      },
    ],
  },

  // ───────────────────────────── TS modules ─────────────────────────────
  {
    id: 'modules',
    title: 'Main-process modules',
    intro: 'TypeScript modules in `src/main/`. `Agent` composes them; the Electron shell (`index.ts`) drives `Agent`, and tests drive it directly with a software key store and the mock server.',
    groups: [
      {
        title: 'Agent — src/main/agent.ts',
        items: [
          {
            id: 'agent',
            kind: 'class',
            name: 'Agent',
            signature: 'new Agent(options: AgentOptions)',
            summary: 'Composes the key store, storage, pairing and jobs. Creates its own `JobRunner`, exposed as `agent.jobs`.',
            params: [
              { name: 'keystore', type: 'KeyStore', desc: 'Native or in-memory key store.' },
              { name: 'store', type: 'Store', desc: 'Paired servers and tokens (must already be loaded).' },
              { name: 'agentVersion', type: 'string', desc: 'Sent as `X-Agent-Version`.' },
              { name: 'fetch?', type: 'FetchLike', desc: 'Override for tests.' },
              { name: 'biometryOnly?', type: 'boolean', desc: 'macOS: require biometrics for identity keys.' },
              { name: 'pollIntervalMs?', type: 'number', desc: 'Pairing poll interval (default 2000).' },
              { name: 'allowInsecureLocalNetwork?', type: 'boolean', desc: 'Developer mode: accept plain `http://` for local-network hosts. Change later with `setAllowInsecureLocalNetwork`.' },
              { name: 'confirm', type: '(req: ConfirmRequest) => Promise<boolean>', desc: 'Shows the confirm window. UX only: the OS prompt is the security boundary.' },
              { name: 'parentWindow?', type: '() => Buffer | undefined', desc: 'Native handle to parent the OS prompt to (HWND on Windows).' },
              { name: 'onPairLink?', type: '(link: PairLink) => void', desc: 'A pair link arrived; prefill the UI.' },
              { name: 'onJobOutcome?', type: '(o: JobOutcome) => void', desc: 'A job finished.' },
              { name: 'onServersChanged?', type: '() => void', desc: 'Pairings were added or removed, or their device type was filled in.' },
            ],
            source: 'src/main/agent.ts#L44',
          },
          {
            id: 'agent-pair',
            kind: 'method',
            name: 'Agent.pair',
            signature: 'agent.pair(originInput: string, codeInput: string, opts?: PairOptions): Promise<PairedServer>',
            summary: 'Normalizes the origin and user code, then runs the full pairing flow (`pair()`). Fires `onServersChanged` on success.',
            throws: 'A user-facing `Error` if the origin isn’t HTTPS or the code is malformed; `PairingError` or `ApiError` from the flow.',
            example: `const server = await agent.pair('https://sign.example.gov.ph', 'k7qm 2xpd', {
  onProgress: (p) => console.log(p.stage),
  signal: AbortSignal.timeout(10 * 60_000),
});`,
            source: 'src/main/agent.ts#L166',
          },
          {
            id: 'agent-handlelink',
            kind: 'method',
            name: 'Agent.handleLink',
            signature: 'agent.handleLink(raw: string): Promise<JobOutcome | null>',
            summary: 'Entry point for every `kukuxsign://` link. A pair link calls `onPairLink` and returns `null`. A job link runs through `JobRunner` and returns its outcome. Unknown shapes return `null`.',
            source: 'src/main/agent.ts#L199',
          },
          {
            id: 'agent-unpair',
            kind: 'method',
            name: 'Agent.unpair',
            signature: 'agent.unpair(serverId: string): Promise<void>',
            summary:
              'Revokes the device on the server, then deletes the local keys and pairing. If the server can’t be reached, the pairing and its signing key go at once, the revoke is queued in `pending-revokes.json` with only the session key kept to authenticate it, and `retryRevokes` finishes it later. A 401 counts as already revoked.',
            source: 'src/main/agent.ts#L218',
          },
          {
            id: 'agent-servers',
            kind: 'method',
            name: 'Agent.servers',
            signature: 'agent.servers(): ServerSummary[]',
            summary: 'Paired servers without secrets or key ids: `id, name, origin, userName, deviceLabel, protection, userPresence, pairedAt, insecure, deviceType, otherDevices`. One per app: a computer holds one signature per server.',
            source: 'src/main/agent.ts#L122',
          },
          {
            id: 'agent-init',
            kind: 'method',
            name: 'Agent.init',
            signature: 'agent.init(): Promise<void>',
            summary: 'Start-up housekeeping: fills in `deviceType` for pairings made before device types existed, then runs `retryRevokes()`.',
            source: 'src/main/agent.ts#L103',
          },
          {
            id: 'agent-retryrevokes',
            kind: 'method',
            name: 'Agent.retryRevokes',
            signature: 'agent.retryRevokes(origin?: string): Promise<void>',
            summary: 'Retries queued revokes (all, or one origin’s). Done on success or 401, when the session key is deleted too; anything else stays queued. Run at start-up, hourly, and by `pair()` before pairing with the same origin.',
            source: 'src/main/agent.ts#L254',
          },
          {
            id: 'agent-refreshotherdevices',
            kind: 'method',
            name: 'Agent.refreshOtherDevices',
            signature: 'agent.refreshOtherDevices(force?: boolean): Promise<boolean>',
            summary: 'Asks each paired server (`GET /status`) for the account’s other signing devices and caches them for `servers()`. Best effort, throttled to once a minute unless forced. Resolves true when something changed.',
            source: 'src/main/agent.ts#L143',
          },
          {
            id: 'agent-thisdevicetype',
            kind: 'method',
            name: 'Agent.thisDeviceType',
            signature: 'agent.thisDeviceType(): Promise<DeviceType>',
            summary: 'This computer’s `detectDeviceType`, computed once per run; `other` if device info can’t be read.',
            source: 'src/main/agent.ts#L114',
          },
          {
            id: 'agent-capabilities',
            kind: 'method',
            name: 'Agent.capabilities',
            signature: 'agent.capabilities(): Promise<Capabilities>',
            summary: 'Forwards `keystore.capabilities()`.',
            source: 'src/main/agent.ts#L95',
          },
          {
            id: 'agent-setallowinsecurelocalnetwork',
            kind: 'method',
            name: 'Agent.setAllowInsecureLocalNetwork',
            signature: 'agent.setAllowInsecureLocalNetwork(on: boolean): void',
            summary: 'Turns Developer mode on or off without a restart. While off, pairings over `http://` fail with a message to turn it on.',
            source: 'src/main/agent.ts#L65',
          },
          {
            id: 'agent-apifor',
            kind: 'method',
            name: 'Agent.apiFor',
            signature: 'agent.apiFor(origin: string): AgentApi',
            summary: 'Builds an `AgentApi` pinned to `origin`. Throws for an `http://` origin while Developer mode is off.',
            source: 'src/main/agent.ts#L73',
          },
          {
            id: 'agent-credentialsfor',
            kind: 'method',
            name: 'Agent.credentialsFor',
            signature: 'agent.credentialsFor(server: PairedServer): Credentials',
            summary: 'Bundles the stored token, user id and a session-key signer for authenticated calls.',
            throws: '`Error` if no token is stored for the server.',
            source: 'src/main/agent.ts#L85',
          },
        ],
      },
      {
        title: 'HTTP client — src/main/api.ts',
        items: [
          {
            id: 'agentapi',
            kind: 'class',
            name: 'AgentApi',
            signature: 'new AgentApi(options: ApiOptions)',
            summary:
              'HTTPS client pinned to one origin. Refuses redirects (`redirect: "error"`), times out after 15 s by default, and signs authenticated requests with the session key.',
            params: [
              { name: 'origin', type: 'string', desc: 'Normalized with `normalizeOrigin`; construction throws for non-HTTPS or malformed origins.' },
              { name: 'agentVersion', type: 'string', desc: 'Sent as `X-Agent-Version`.' },
              { name: 'fetch?', type: 'FetchLike', desc: 'Defaults to global `fetch`.' },
              { name: 'timeoutMs?', type: 'number', desc: 'Default 15000.' },
              { name: 'now?', type: '() => number', desc: 'Clock for tests.' },
              { name: 'allowInsecureLocalNetwork?', type: 'boolean', desc: 'See `OriginPolicy`.' },
            ],
            throws: '`Error` if the origin is refused.',
            source: 'src/main/api.ts#L149',
          },
          { id: 'agentapi-lookuppairing', kind: 'method', name: 'AgentApi.lookupPairing', signature: 'lookupPairing(userCode: string): Promise<PairingLookup>', summary: 'Calls `POST /pairings/lookup`.', endpoint: 'post-pairings-lookup', source: 'src/main/api.ts#L166' },
          { id: 'agentapi-claimpairing', kind: 'method', name: 'AgentApi.claimPairing', signature: 'claimPairing(pairing: string, claim: PairingClaim): Promise<{ status: string; poll_secret: string }>', summary: 'Calls `POST /pairings/{pairing}/claim`.', endpoint: 'post-pairings-claim', source: 'src/main/api.ts#L170' },
          { id: 'agentapi-pollpairing', kind: 'method', name: 'AgentApi.pollPairing', signature: 'pollPairing(pairing: string, pollSecret: string): Promise<PairingStatus>', summary: 'Calls `POST /pairings/{pairing}/poll`.', endpoint: 'post-pairings-poll', source: 'src/main/api.ts#L174' },
          { id: 'agentapi-status', kind: 'method', name: 'AgentApi.status', signature: 'status(creds: Credentials): Promise<AgentStatus>', summary: 'Calls `GET /status` (authenticated).', endpoint: 'get-status', source: 'src/main/api.ts#L180' },
          { id: 'agentapi-claimjob', kind: 'method', name: 'AgentApi.claimJob', signature: 'claimJob(creds: Credentials, jobId: string, linkToken: string): Promise<AgentJob>', summary: 'Calls `POST /jobs/{job}/claim`: consumes the one-time link token and binds the job to this device.', endpoint: 'post-jobs-claim', source: 'src/main/api.ts#L185' },
          { id: 'agentapi-completejob', kind: 'method', name: 'AgentApi.completeJob', signature: 'completeJob(creds: Credentials, jobId: string, proof: string): Promise<{ status: string }>', summary: 'Calls `POST /jobs/{job}/complete` with the base64 identity-key signature.', endpoint: 'post-jobs-complete', source: 'src/main/api.ts#L189' },
          { id: 'agentapi-rejectjob', kind: 'method', name: 'AgentApi.rejectJob', signature: 'rejectJob(creds: Credentials, jobId: string, reason: string): Promise<{ status: string }>', summary: 'Calls `POST /jobs/{job}/reject`.', endpoint: 'post-jobs-reject', source: 'src/main/api.ts#L193' },
          { id: 'agentapi-unpair', kind: 'method', name: 'AgentApi.unpair', signature: 'unpair(creds: Credentials): Promise<void>', summary: 'Calls `DELETE /device`: revokes this device’s token on the server.', endpoint: 'delete-device', source: 'src/main/api.ts#L198' },
          {
            id: 'apierror',
            kind: 'class',
            name: 'ApiError',
            signature: 'class ApiError extends Error { status: number; code: string; details: Record<string, unknown> }',
            summary:
              'Thrown for any non-2xx response. `code` comes from `error.code`, or is `http_<status>`. A non-JSON body gives `invalid_response`. `details` holds the whole parsed body (for example `min_version`).',
            params: [
              { name: 'outdated', type: 'getter → boolean', desc: 'True for 426 or `agent_outdated`.' },
              { name: 'unauthorized', type: 'getter → boolean', desc: 'True for 401: token revoked or device unpaired on the web.' },
            ],
            source: 'src/main/api.ts#L110',
          },
          {
            id: 'credentials',
            kind: 'type',
            name: 'Credentials',
            signature: `interface Credentials {
  token: string;
  userId: string;
  signWithSessionKey(message: Buffer): Promise<Buffer>;
}`,
            summary: 'What an authenticated call needs. The signer uses the session key, so no user prompt appears.',
            source: 'src/main/api.ts#L131',
          },
        ],
      },
      {
        title: 'Pairing — src/main/pairing.ts',
        items: [
          {
            id: 'pair',
            kind: 'function',
            name: 'pair',
            signature: 'pair(deps: PairingDeps, code: string, opts?: PairOptions): Promise<PairedServer>',
            summary:
              'The device-code pairing flow: look up the code → create identity key (with user presence) and session key (without) → sign the `register_agent` proof (Touch ID / Hello) → claim → poll until confirmed.',
            params: [
              { name: 'deps.keystore', type: 'KeyStore', desc: '' },
              { name: 'deps.store', type: 'Store', desc: '' },
              { name: 'deps.api', type: 'AgentApi', desc: 'Already pinned to the origin.' },
              { name: 'deps.agentVersion', type: 'string', desc: '' },
              { name: 'deps.biometryOnly?', type: 'boolean', desc: '' },
              { name: 'deps.pollIntervalMs?', type: 'number', desc: 'Default 2000.' },
              { name: 'deps.sleep?', type: '(ms, signal?) => Promise<void>', desc: 'For tests.' },
              { name: 'opts.onProgress?', type: '(p: PairingProgress) => void', desc: 'Stages: `looking_up`, `already_paired_locally`, `creating_keys`, `awaiting_confirmation`, `paired`.' },
              { name: 'opts.signal?', type: 'AbortSignal', desc: 'Cancels the flow.' },
              { name: 'opts.confirmRepair?', type: '(existing: PairedServer) => Promise<boolean>', desc: 'This account is already paired for the app: true re-pairs with new keys, false stops before anything is created. Without it, re-pairing goes ahead.' },
            ],
            throws: '`PairingError` (`origin_mismatch`, `invalid_response`, `presence_unavailable`, `rejected`, `expired`, `aborted`, `app_already_paired`, `machine_already_paired`, `device_type_not_allowed`), `ApiError`, or key store errors.',
            notes: [
              'One signature per app per computer. Right after the lookup, before any key or OS prompt: a detected type in `blocked_device_types` stops with `device_type_not_allowed`; a different account already paired for this server stops with `app_already_paired`; the same account triggers `already_paired_locally` and `confirmRepair`.',
              'The server enforces both again at claim (`machine_already_paired`, `device_type_not_allowed`), mapped to the same messages.',
              'A same-account re-pair updates the server’s existing device (`rebound: true` in `paired`), keeping its uuid and history.',
              'Each pairing gets fresh keys under a new key id (`ds.<hash16>.<rand8>.identity|session`), so a failed re-pair never breaks the existing pairing.',
              'Old keys for the same server are deleted only after the new pairing is saved. Keys created by a failed attempt are always deleted.',
              'The deadline is the lookup’s `expires_at`, or 10 minutes if it can’t be parsed.',
            ],
            source: 'src/main/pairing.ts#L83',
          },
          {
            id: 'pairingerror',
            kind: 'class',
            name: 'PairingError',
            signature: "class PairingError extends Error { code: PairingErrorCode; serverId?: string }",
            summary: 'Pairing failures with user-facing messages. Codes: `origin_mismatch`, `invalid_response`, `presence_unavailable`, `rejected`, `expired`, `aborted`, `app_already_paired` (with `serverId`, the pairing to unpair first), `machine_already_paired`, `device_type_not_allowed`.',
            source: 'src/main/pairing.ts#L48',
          },
          {
            id: 'deletekeys',
            kind: 'function',
            name: 'deleteKeys',
            signature: 'deleteKeys(keystore: KeyStore, keyIds: string[]): Promise<void>',
            summary: 'Deletes each key, ignoring errors (for example, keys that are already gone).',
            source: 'src/main/pairing.ts#L292',
          },
          {
            id: 'pairingprogress',
            kind: 'type',
            name: 'PairingProgress',
            signature: `type PairingProgress =
  | { stage: 'looking_up' }
  | { stage: 'already_paired_locally'; serverName: string; userName: string }
  | { stage: 'creating_keys'; serverName: string }
  | { stage: 'awaiting_confirmation'; serverName: string; origin: string; deviceLabel: string;
      existingDevice?: { label: string; deviceType?: DeviceType } }
  | { stage: 'paired'; server: PairedServer; rebound: boolean };`,
            summary: 'Reported through `opts.onProgress`.',
            source: 'src/main/pairing.ts#L22',
          },
        ],
      },
      {
        title: 'Signing jobs — src/main/jobs.ts',
        items: [
          {
            id: 'jobrunner',
            kind: 'class',
            name: 'JobRunner',
            signature: 'new JobRunner(deps: JobDeps)',
            summary: 'Runs signing jobs one at a time, so only one confirm window and one OS prompt are ever up.',
            params: [
              { name: 'keystore', type: 'KeyStore', desc: '' },
              { name: 'store', type: 'Store', desc: '' },
              { name: 'apiFor', type: '(server) => AgentApi', desc: '' },
              { name: 'credentialsFor', type: '(server) => Credentials', desc: '' },
              { name: 'confirm', type: '(req: ConfirmRequest) => Promise<boolean>', desc: 'Resolves true on Approve.' },
              { name: 'parentWindow?', type: '() => Buffer | undefined', desc: '' },
              { name: 'onUnauthorized?', type: '(server) => void', desc: 'Called on 401 from claim; `Agent` forgets the pairing.' },
            ],
            source: 'src/main/jobs.ts#L41',
          },
          {
            id: 'jobrunner-handle',
            kind: 'method',
            name: 'JobRunner.handle',
            signature: 'jobRunner.handle(link: JobLink): Promise<JobOutcome>',
            summary:
              'Claim the job from the paired server’s stored origin → validate → confirm window → sign the `sign_receipt` message with the identity key → complete.',
            returns: `| { result: 'completed'; jobId }
| { result: 'rejected'; jobId; reason: 'declined' | 'os_prompt_cancelled' }
| { result: 'ignored'; reason: 'unknown server' | 'already in progress' }
| { result: 'failed'; jobId; error; code? }`,
            notes: [
              'An invalid job is rejected on the server with `invalid_job`.',
              'Declining the confirm window rejects with `declined`. Cancelling the OS prompt (`E_CANCELLED`) rejects with `os_prompt_cancelled`.',
              'A job id already in progress is ignored, so a double-clicked link doesn’t prompt twice.',
            ],
            source: 'src/main/jobs.ts#L48',
          },
          {
            id: 'validatejob',
            kind: 'function',
            name: 'validateJob',
            signature: 'validateJob(job: AgentJob, link: JobLink, server: PairedServer): string | null',
            summary: 'Returns a problem description, or `null` if the job is acceptable.',
            notes: [
              '`job.uuid` must equal the link’s job id.',
              '`purpose` must be `sign_receipt`.',
              '`user_id` must equal the paired user.',
              '`document.title` and `signer.name` must be non-empty and at most 300 characters.',
              'The canonical message must build (valid nonce and payload hash).',
            ],
            source: 'src/main/jobs.ts#L110',
          },
        ],
      },
      {
        title: 'Links and origins — src/main/protocol.ts',
        items: [
          {
            id: 'parselink',
            kind: 'function',
            name: 'parseLink',
            signature: 'parseLink(raw: string, policy?: OriginPolicy): AgentLink | null',
            summary: 'Parses a `kukuxsign://` link into a `JobLink` or `PairLink`. Anything that doesn’t match exactly (including links over 2048 characters) returns `null`.',
            example: `parseLink('kukuxsign://pair?o=https%3A%2F%2Fsign.example.gov.ph&c=k7qm2xpd');
// → { kind: 'pair', origin: 'https://sign.example.gov.ph', code: 'K7QM-2XPD' }`,
            source: 'src/main/protocol.ts#L40',
          },
          {
            id: 'normalizeusercode',
            kind: 'function',
            name: 'normalizeUserCode',
            signature: 'normalizeUserCode(input: string): string | null',
            summary: 'Returns `"XXXX-XXXX"` or `null`. Accepts lower case, spaces and a missing dash. The alphabet excludes 0/O and 1/I/L.',
            source: 'src/main/protocol.ts#L80',
          },
          {
            id: 'normalizeorigin',
            kind: 'function',
            name: 'normalizeOrigin',
            signature: 'normalizeOrigin(input: string, policy?: OriginPolicy): string | null',
            summary:
              'Returns the bare origin (`scheme://host[:port]`) or `null`. HTTPS only, except local-network hosts when `allowInsecureLocalNetwork` is set. Paths, credentials, queries and fragments are rejected.',
            source: 'src/main/protocol.ts#L91',
          },
          {
            id: 'islocalnetworkhost',
            kind: 'function',
            name: 'isLocalNetworkHost',
            signature: 'isLocalNetworkHost(hostname: string): boolean',
            summary: 'Loopback, private (RFC 1918), link-local and IPv6 unique-local addresses, plus `*.local`, `*.test` and `*.localhost` names.',
            source: 'src/main/protocol.ts#L114',
          },
          {
            id: 'linkfromargv',
            kind: 'function',
            name: 'linkFromArgv',
            signature: 'linkFromArgv(argv: string[]): string | null',
            summary: 'Finds a `kukuxsign://` link in process argv (Windows first launch and second instance).',
            source: 'src/main/protocol.ts#L132',
          },
          {
            id: 'scheme',
            kind: 'constant',
            name: 'SCHEME',
            signature: "const SCHEME = 'kukuxsign'",
            summary: 'The registered URL scheme.',
            source: 'src/main/protocol.ts#L8',
          },
        ],
      },
      {
        title: 'Device types — src/main/device-type.ts',
        items: [
          {
            id: 'device-types',
            kind: 'type',
            name: 'DeviceType',
            signature: `type DeviceType =
  | 'macbook' | 'macbook_air' | 'macbook_pro' | 'imac' | 'mac_mini' | 'mac_studio' | 'mac_pro'
  | 'laptop' | 'convertible' | 'desktop' | 'all_in_one' | 'mini_pc' | 'server' | 'chromebook'
  | 'tablet' | 'ipad' | 'android_tablet'
  | 'iphone' | 'android' | 'phone'
  | 'virtual_machine' | 'other';`,
            summary: 'The catalogue, in `DEVICE_TYPES` order, shared with the package’s `DeviceType` enum through `test/fixtures/device-types.json`. Phones, tablets and Chromebooks are on hold until a mobile app exists: nothing reports them yet. A label for people, never a security signal.',
            source: 'src/main/device-type.ts#L10',
          },
          {
            id: 'detectdevicetype',
            kind: 'function',
            name: 'detectDeviceType',
            signature: 'detectDeviceType(d: DeviceInfo): DeviceType',
            summary: 'What this computer is. A VM first (firmware flag, `VirtualMac*`, or a hypervisor vendor in the SMBIOS manufacturer/product). macOS: the Mac family from the marketing name or identifier. Windows: Boot Camp Macs by family, then the SMBIOS chassis type, with the battery overriding a "Desktop" chassis; unknown chassis types fall back to the battery.',
            source: 'src/main/device-type.ts#L126',
          },
          {
            id: 'categoryof',
            kind: 'function',
            name: 'categoryOf',
            signature: "categoryOf(type: DeviceType): 'computer' | 'tablet' | 'phone' | 'virtual' | 'other'",
            summary: 'The group a type belongs to.',
            source: 'src/main/device-type.ts#L46',
          },
        ],
      },
      {
        title: 'Storage — src/main/store.ts',
        items: [
          {
            id: 'store',
            kind: 'class',
            name: 'Store',
            signature: 'new Store(dir: string, cipher: TokenCipher)',
            summary:
              '`servers.json` holds public metadata (origin, ids, key ids), one entry per server: a computer holds one signature per app. Agent tokens are kept separately in `tokens.json`, encrypted with the `TokenCipher`. `pending-revokes.json` holds unpairs the server hasn’t acknowledged, their tokens sealed the same way. Files are written atomically with mode 0600 in a 0700 directory.',
            notes: ['Call `load()` before anything else; every other method throws until then.'],
            source: 'src/main/store.ts#L80',
          },
          { id: 'store-load', kind: 'method', name: 'Store.load', signature: 'load(): Promise<void>', summary: 'Reads both files. Missing or malformed files start empty.', source: 'src/main/store.ts#L91' },
          { id: 'store-list', kind: 'method', name: 'Store.list', signature: 'list(): PairedServer[]', summary: 'Copies of every paired server.', source: 'src/main/store.ts#L100' },
          { id: 'store-get', kind: 'method', name: 'Store.get', signature: 'get(serverId: string): PairedServer | null', summary: 'One server by id.', source: 'src/main/store.ts#L105' },
          { id: 'store-findbyorigin', kind: 'method', name: 'Store.findByOrigin', signature: 'findByOrigin(origin: string): PairedServer | null', summary: 'One server by origin.', source: 'src/main/store.ts#L111' },
          { id: 'store-save', kind: 'method', name: 'Store.save', signature: 'save(server: PairedServer, token: string): Promise<void>', summary: 'Adds or replaces a server and its encrypted token.', throws: '`Error` if the cipher is unavailable, so a token is never stored in the clear.', source: 'src/main/store.ts#L117' },
          { id: 'store-token', kind: 'method', name: 'Store.token', signature: 'token(serverId: string): string | null', summary: 'Decrypts the token; `null` if missing or undecryptable.', source: 'src/main/store.ts#L135' },
          { id: 'store-update', kind: 'method', name: 'Store.update', signature: 'update(server: PairedServer): Promise<void>', summary: 'Rewrites a pairing’s metadata, keeping its token.', throws: '`Error` if there’s no pairing with that id.', source: 'src/main/store.ts#L128' },
          { id: 'store-queuerevoke', kind: 'method', name: 'Store.queueRevoke', signature: 'queueRevoke(revoke: PendingRevoke, token: string): Promise<void>', summary: 'Queues an unpair whose server-side revoke failed, with its token sealed.', throws: '`Error` if the cipher is unavailable.', source: 'src/main/store.ts#L175' },
          { id: 'store-pendingrevokes', kind: 'method', name: 'Store.pendingRevokes', signature: 'pendingRevokes(serverId?: string): PendingRevoke[]', summary: 'Queued revokes, without their tokens.', source: 'src/main/store.ts#L156' },
          { id: 'store-revoketoken', kind: 'method', name: 'Store.revokeToken', signature: 'revokeToken(deviceUuid: string): string | null', summary: 'Decrypts a queued revoke’s token.', source: 'src/main/store.ts#L163' },
          { id: 'store-droprevoke', kind: 'method', name: 'Store.dropRevoke', signature: 'dropRevoke(deviceUuid: string): Promise<void>', summary: 'Removes a revoke from the queue.', source: 'src/main/store.ts#L187' },
          { id: 'store-remove', kind: 'method', name: 'Store.remove', signature: 'remove(serverId: string): Promise<void>', summary: 'Removes the server and its token.', source: 'src/main/store.ts#L146' },
          {
            id: 'sealedtokencipher',
            kind: 'function',
            name: 'sealedTokenCipher',
            signature: 'sealedTokenCipher(sealer: Sealer): TokenCipher',
            summary: 'A `TokenCipher` that seals tokens to the Secure Enclave (ECDH + AES-GCM). Used by free macOS builds so the keychain never prompts after an update. Otherwise Electron `safeStorage` (Keychain / DPAPI) is used.',
            source: 'src/main/store.ts#L56',
          },
          {
            id: 'pairedserver',
            kind: 'type',
            name: 'PairedServer',
            signature: `interface PairedServer {
  id: string; name: string; origin: string; salt: string;
  userId: string; userName: string;
  deviceUuid: string; deviceLabel: string;
  identityKeyId: string; sessionKeyId: string;
  algorithm: 'ES256' | 'RS256';
  protection: 'secure_enclave' | 'tpm' | 'software';
  userPresence: boolean;
  pairedAt: string; // ISO 8601
  deviceType?: DeviceType; // filled in at start-up for older pairings
}`,
            summary: 'One entry in `servers.json`.',
            source: 'src/main/store.ts#L20',
          },
        ],
      },
      {
        title: 'Key store wrapper — src/main/keystore.ts',
        items: [
          {
            id: 'loadnativekeystore',
            kind: 'function',
            name: 'loadNativeKeyStore',
            signature: 'loadNativeKeyStore(appRoot: string, options: { keyDirectory: string }): NativeModule',
            summary: 'Loads `native/build/Release/keystore.node` (from `app.asar.unpacked` in packaged builds) and calls `configure({ keyDirectory })`.',
            source: 'src/main/keystore.ts#L82',
          },
          {
            id: 'iskeystoreerror',
            kind: 'function',
            name: 'isKeyStoreError',
            signature: 'isKeyStoreError(err: unknown, code: KeyStoreErrorCode): boolean',
            summary: 'Checks `err.code` set by the native module.',
            example: `try { await keystore.sign(id, msg, reason); }
catch (err) { if (isKeyStoreError(err, 'E_CANCELLED')) { /* user dismissed the prompt */ } }`,
            source: 'src/main/keystore.ts#L59',
          },
          {
            id: 'keystore-interface',
            kind: 'type',
            name: 'KeyStore',
            signature: `interface KeyStore {
  capabilities(): Promise<Capabilities>;
  createKey(o: { keyId: string; requireUserPresence: boolean; biometryOnly?: boolean }): Promise<KeyInfo>;
  findKey(keyId: string): Promise<KeyInfo | null>;
  sign(keyId: string, message: Buffer, reason: string, parentWindow?: Buffer): Promise<Buffer>;
  attest(keyId: string): Promise<AttestationResult | null>;
  deleteKey(keyId: string): Promise<void>;
  deviceInfo(salt: string): Promise<DeviceInfo>;
}`,
            summary: 'The contract every key store implements (native addon, or `test/support/memory-keystore.ts`). See [Native addon](#/api/native) for each call.',
            source: 'src/main/keystore.ts#L45',
          },
          {
            id: 'keyinfo',
            kind: 'type',
            name: 'KeyInfo',
            signature: `interface KeyInfo {
  keyId: string;
  algorithm: 'ES256' | 'RS256';
  spki: Buffer;            // SubjectPublicKeyInfo DER
  protection: 'secure_enclave' | 'tpm' | 'software';
  userPresence: boolean;   // OS-enforced Touch ID / Hello / password on every use
}`,
            summary: 'Returned by `createKey` and `findKey`.',
            source: 'src/main/keystore.ts#L8',
          },
          {
            id: 'deviceinfo-type',
            kind: 'type',
            name: 'DeviceInfo',
            signature: `interface DeviceInfo {
  platform: 'macos' | 'windows';
  osVersion: string;
  model: string;            // e.g. "MacBook Pro"
  modelIdentifier: string;  // e.g. "Mac15,3"
  formFactor: 'laptop' | 'desktop' | 'unknown';
  hostname: string;
  hardwareIdHash: string;   // sha256(serverSalt || hardware uuid), never the raw uuid; "" if unreadable
  chassisType: number | null; // SMBIOS type 3 chassis type (Windows); null on macOS
  virtual: boolean;           // firmware reports a VM (kern.hv_vmm_present / SMBIOS type 0 bit)
}`,
            summary: 'Returned by `deviceInfo(salt)`. `detectDeviceType` turns it into a `DeviceType`.',
            source: 'src/main/keystore.ts#L30',
          },
        ],
      },
      {
        title: 'Shell helpers',
        items: [
          { id: 'startupdater', kind: 'function', name: 'startUpdater', signature: 'startUpdater(onChange: (status: UpdateView) => void): void', summary: 'Packaged builds check at startup and every six hours. Signed and Windows builds download in the background; free macOS builds announce the release.', source: 'src/main/updater.ts#L41' },
          { id: 'checkforupdates', kind: 'function', name: 'checkForUpdates', signature: 'checkForUpdates(opts?: { background?: boolean }): Promise<void>', summary: 'Reads the latest GitHub release. Background checks (and a server 426) stay quiet on errors; manual checks report them.', source: 'src/main/updater.ts#L70' },
          { id: 'installupdate', kind: 'function', name: 'installUpdate', signature: 'installUpdate(): Promise<void>', summary: 'Downloads (electron-updater, or the free-macOS bundle swap in self-update.ts), restarts to install, or opens the release page in dev builds.', source: 'src/main/updater.ts#L99' },
          { id: 'fetchlatestrelease', kind: 'function', name: 'fetchLatestRelease', signature: 'fetchLatestRelease(fetch: FetchLike): Promise<ReleaseInfo>', summary: 'GitHub Releases API → `{ version, name, notes, url, publishedAt }`. Links outside this repository fall back to the releases page.', source: 'src/main/release.ts#L17' },
          { id: 'compareversions', kind: 'function', name: 'compareVersions', signature: 'compareVersions(a: string, b: string): number', summary: 'Numeric `x.y.z` comparison; pre-release suffixes are ignored.', source: 'src/main/release.ts#L58' },
          { id: 'settingsstore', kind: 'class', name: 'SettingsStore', signature: 'new SettingsStore(dir: string)', summary: '`settings.json` in userData: `{ developerMode }`. `load()`, `get()`, `update(patch)`.', source: 'src/main/settings.ts#L14' },
          { id: 'registerappscheme', kind: 'function', name: 'registerAppScheme', signature: 'registerAppScheme(): void', summary: 'Registers the privileged `app://` scheme. Must run before app `ready`.', source: 'src/main/app-protocol.ts#L29' },
          { id: 'handleappscheme', kind: 'function', name: 'handleAppScheme', signature: 'handleAppScheme(rendererDir: string): void', summary: 'Serves the bundled UI from `app://agent/`, GET only, confined to `rendererDir`, with a strict CSP sent as a response header.', source: 'src/main/app-protocol.ts#L33' },
          { id: 'appurl', kind: 'function', name: 'appUrl', signature: 'appUrl(hash: string): string', summary: 'Returns `app://agent/index.html#<hash>`.', source: 'src/main/app-protocol.ts#L59' },
          { id: 'signed-build', kind: 'constant', name: 'SIGNED_BUILD', signature: "const SIGNED_BUILD = process.env.KUKUX_SIGNED_BUILD === 'true'", summary: 'Baked in by `scripts/build.mjs`. False for free builds.', source: 'src/main/build-info.ts#L5' },
          { id: 'avoid-keychain', kind: 'constant', name: 'AVOID_KEYCHAIN', signature: "const AVOID_KEYCHAIN = process.platform === 'darwin' && !SIGNED_BUILD", summary: 'Free macOS builds keep out of the keychain entirely: Chromium gets a mock keychain and tokens are sealed to the Secure Enclave.', source: 'src/main/build-info.ts#L14' },
        ],
      },
    ],
  },

  // ───────────────────────────── Native ─────────────────────────────
  {
    id: 'native',
    title: 'Native addon (keystore.node)',
    intro:
      'N-API module in `native/`. JavaScript holds key ids and receives public keys and signatures, never private key material. ' +
      'Every async call runs on a worker thread and returns a Promise, because `sign()` blocks while Touch ID / Hello is up. Calls are serialized with one mutex, so at most one OS prompt shows at a time. ' +
      'Key ids must match `[A-Za-z0-9._-]{1,128}`.',
    groups: [
      {
        title: 'Keys',
        items: [
          {
            id: 'native-capabilities',
            kind: 'function',
            name: 'capabilities',
            signature: 'capabilities(): Promise<{ hardware: boolean; userPresence: boolean; attestation: boolean }>',
            summary: 'What this machine supports: a hardware-backed store, OS-enforced user presence, and key attestation.',
            source: 'native/src/addon.cc#L123',
          },
          {
            id: 'native-createkey',
            kind: 'function',
            name: 'createKey',
            signature: 'createKey({ keyId, requireUserPresence, biometryOnly? }): Promise<KeyInfo>',
            summary: 'Creates a non-exportable key in the Secure Enclave, the TPM (Windows Hello), or software as a fallback.',
            params: [
              { name: 'keyId', type: 'string', desc: '`[A-Za-z0-9._-]{1,128}`.' },
              { name: 'requireUserPresence', type: 'boolean', desc: 'True for identity keys, false for session keys.' },
              { name: 'biometryOnly?', type: 'boolean', desc: 'macOS: demand biometrics (invalidated on enrolment change) instead of “biometrics or login password”.' },
            ],
            throws: '`E_EXISTS`, `E_UNSUPPORTED`, `E_INTERNAL`.',
            notes: [
              'macOS signed builds: Secure Enclave via the data-protection keychain.',
              'macOS free builds: Secure Enclave via CryptoKit, stored as an SE-wrapped blob in the key directory.',
              'Windows: Windows Hello (RS256, TPM-backed) for identity keys; TPM (Platform Crypto Provider) or software CNG otherwise.',
            ],
            source: 'native/src/addon.cc#L136',
          },
          {
            id: 'native-findkey',
            kind: 'function',
            name: 'findKey',
            signature: 'findKey(keyId: string): Promise<KeyInfo | null>',
            summary: 'Looks up an existing key.',
            source: 'native/src/addon.cc#L151',
          },
          {
            id: 'native-sign',
            kind: 'function',
            name: 'sign',
            signature: 'sign(keyId: string, message: Buffer, reason: string, parentWindow?: Buffer): Promise<Buffer>',
            summary:
              'Signs `message`. The addon hashes it with SHA-256 itself, so JavaScript can’t ask a key to sign an arbitrary digest. ES256 returns ASN.1 DER; RS256 returns PKCS#1 v1.5.',
            params: [
              { name: 'keyId', type: 'string', desc: '' },
              { name: 'message', type: 'Buffer', desc: 'The canonical message bytes (not a digest).' },
              { name: 'reason', type: 'string', desc: 'Shown in the Touch ID / Hello prompt, e.g. `sign "Report" as Juan`.' },
              { name: 'parentWindow?', type: 'Buffer', desc: '`BrowserWindow.getNativeWindowHandle()`: the HWND on Windows; unused on macOS.' },
            ],
            throws: '`E_CANCELLED` when the user dismisses the prompt, `E_NOT_FOUND`, `E_INTERNAL`.',
            source: 'native/src/addon.cc#L162',
          },
          {
            id: 'native-attest',
            kind: 'function',
            name: 'attest',
            signature: 'attest(keyId: string): Promise<{ format: string; statement: Buffer; chain: Buffer[] } | null>',
            summary: 'Key attestation when the platform supports it (e.g. `windows-hello-tpm`); `null` otherwise.',
            source: 'native/src/addon.cc#L186',
          },
          {
            id: 'native-deletekey',
            kind: 'function',
            name: 'deleteKey',
            signature: 'deleteKey(keyId: string): Promise<void>',
            summary: 'Deletes a key.',
            source: 'native/src/addon.cc#L204',
          },
        ],
      },
      {
        title: 'Device and configuration',
        items: [
          {
            id: 'native-deviceinfo',
            kind: 'function',
            name: 'deviceInfo',
            signature: 'deviceInfo(salt: string): Promise<DeviceInfo>',
            summary: 'Platform, OS version, model, form factor, hostname, `sha256_hex(salt ‖ hardware uuid)`, the SMBIOS chassis type (Windows) and whether the firmware reports a virtual machine. The raw hardware uuid never leaves the addon; `hardwareIdHash` is `""` if it can’t be read, and the agent then sends `null`.',
            source: 'native/src/addon.cc#L211',
          },
          {
            id: 'native-configure',
            kind: 'function',
            name: 'configure',
            signature: 'configure({ keyDirectory: string }): void',
            summary: 'Sets where file-backed keys live (macOS SE blobs). The app uses `<userData>/keys`; the default is `~/Library/Application Support/Kukux Sign Agent/keys`.',
            throws: '`TypeError` if `keyDirectory` isn’t an absolute path.',
            source: 'native/src/addon.cc#L233',
          },
        ],
      },
      {
        title: 'Sealing (synchronous)',
        intro: 'Synchronous on purpose (a few ms, never prompts) so the token store can stay synchronous. They don’t take the mutex that a pending OS prompt holds.',
        items: [
          { id: 'native-sealingavailable', kind: 'function', name: 'sealingAvailable', signature: 'sealingAvailable(): boolean', summary: 'True on Macs with a Secure Enclave. Always false on Windows, which uses safeStorage (DPAPI).', source: 'native/src/addon.cc#L252' },
          { id: 'native-sealdata', kind: 'function', name: 'sealData', signature: 'sealData(plain: Buffer): Buffer', summary: 'Seals a small secret to a Secure Enclave key-agreement key (ECDH + AES-GCM). No prompt.', source: 'native/src/addon.cc#L270' },
          { id: 'native-opendata', kind: 'function', name: 'openData', signature: 'openData(sealed: Buffer): Buffer', summary: 'Opens data sealed by `sealData` on this Mac.', throws: 'An `Error` with `code` set on failure.', source: 'native/src/addon.cc#L271' },
          { id: 'native-probeexportable', kind: 'function', name: '_probeExportable', signature: '_probeExportable(keyId: string): Promise<boolean>', summary: 'Test hook: true if the private key can be exported. Must always be false.', source: 'native/src/addon.cc#L274' },
        ],
      },
      {
        title: 'Error codes',
        items: [
          {
            id: 'native-errors',
            kind: 'error',
            name: 'err.code',
            summary: 'Set on errors thrown by the addon. Check with `isKeyStoreError(err, code)`.',
            table: [
              ['E_NOT_FOUND', 'The key id doesn’t exist.'],
              ['E_EXISTS', 'A key with that id already exists.'],
              ['E_CANCELLED', 'The user dismissed the Touch ID / Hello / password prompt.'],
              ['E_UNSUPPORTED', 'The operation isn’t available on this machine.'],
              ['E_INTERNAL', 'Any other platform failure.'],
            ],
            source: 'native/include/keystore.h#L68',
          },
        ],
      },
    ],
  },

  // ───────────────────────────── IPC ─────────────────────────────
  {
    id: 'ipc',
    title: 'Renderer bridge (window.agent)',
    intro:
      'The preload exposes a deliberately narrow API to the sandboxed renderer through `contextBridge`. There is no generic `sign(bytes)`. ' +
      'The main process accepts IPC only from its own bundled page (`app://agent/index.html`).',
    groups: [
      {
        title: 'Calls (renderer → main)',
        items: [
          { id: 'ipc-getstatus', kind: 'ipc', name: 'getStatus', channel: 'agent:get-status', signature: 'window.agent.getStatus(): Promise<StatusView>', summary: 'Version, platform, capabilities and paired servers.', returns: `{ version: string; platform: 'macos' | 'windows' | 'other';
  capabilities: { hardware; userPresence; attestation };
  servers: ServerView[];               // each has insecure, deviceType and otherDevices
  developerMode: { on; locked } }`, source: 'src/shared/ipc.ts#L113' },
          { id: 'ipc-startpairing', kind: 'ipc', name: 'startPairing', channel: 'agent:start-pairing', signature: 'window.agent.startPairing({ origin, code }): Promise<PairingResult>', summary: 'Runs `Agent.pair`. Starting a new pairing aborts one in progress. Never throws: errors come back as `{ ok: false, error, code? }`; with `code: app_already_paired`, `serverId` and `serverName` name the pairing to unpair first.', returns: '`{ ok: true; serverName; rebound } | { ok: false; error; code?; serverId?; serverName? }`', source: 'src/shared/ipc.ts#L114' },
          { id: 'ipc-confirmrepair', kind: 'ipc', name: 'confirmRepair', channel: 'agent:confirm-repair', signature: 'window.agent.confirmRepair(repair: boolean): Promise<void>', summary: 'Answers an `already_paired_locally` progress: true re-pairs this account with new keys, false stops before anything is created.', source: 'src/shared/ipc.ts#L117' },
          { id: 'ipc-cancelpairing', kind: 'ipc', name: 'cancelPairing', channel: 'agent:cancel-pairing', signature: 'window.agent.cancelPairing(): Promise<void>', summary: 'Aborts the pairing in progress.', source: 'src/shared/ipc.ts#L115' },
          { id: 'ipc-getjob', kind: 'ipc', name: 'getJob', channel: 'agent:get-job', signature: 'window.agent.getJob(id: string): Promise<JobView | null>', summary: 'The job waiting in the confirm window, or `null`.', returns: `{ id; serverName; origin; documentTitle; signerName; purpose;
  expiresAt; protection; userPresence }`, source: 'src/shared/ipc.ts#L118' },
          { id: 'ipc-approvejob', kind: 'ipc', name: 'approveJob', channel: 'agent:approve-job', signature: 'window.agent.approveJob(id: string): Promise<void>', summary: 'Approve in the confirm window. The OS prompt follows; it is the real security boundary.', source: 'src/shared/ipc.ts#L119' },
          { id: 'ipc-rejectjob', kind: 'ipc', name: 'rejectJob', channel: 'agent:reject-job', signature: 'window.agent.rejectJob(id: string): Promise<void>', summary: 'Decline in the confirm window. The server is told `declined`.', source: 'src/shared/ipc.ts#L120' },
          { id: 'ipc-unpair', kind: 'ipc', name: 'unpair', channel: 'agent:unpair', signature: 'window.agent.unpair(serverId: string): Promise<void>', summary: 'Runs `Agent.unpair`.', source: 'src/shared/ipc.ts#L121' },
          { id: 'ipc-setdevelopermode', kind: 'ipc', name: 'setDeveloperMode', channel: 'agent:set-developer-mode', signature: 'window.agent.setDeveloperMode(on: boolean): Promise<void>', summary: 'Turning it on asks for confirmation in a native dialog first. No effect under `npm run dev`, where it is always on.', source: 'src/shared/ipc.ts#L122' },
          { id: 'ipc-getupdate', kind: 'ipc', name: 'getUpdate', channel: 'agent:get-update', signature: 'window.agent.getUpdate(): Promise<UpdateView>', summary: 'The current update state.', returns: `| { state: 'idle' | 'checking' }
| { state: 'up_to_date'; checkedAt }
| { state: 'available'; release; install: 'download' | 'open_page' }
| { state: 'downloading'; release; percent }
| { state: 'ready'; release }
| { state: 'error'; message }`, source: 'src/shared/ipc.ts#L123' },
          { id: 'ipc-checkforupdates', kind: 'ipc', name: 'checkForUpdates', channel: 'agent:check-for-updates', signature: 'window.agent.checkForUpdates(): Promise<void>', summary: 'Checks the latest GitHub release now. Progress arrives through `onUpdateChanged`.', source: 'src/shared/ipc.ts#L124' },
          { id: 'ipc-installupdate', kind: 'ipc', name: 'installUpdate', channel: 'agent:install-update', signature: 'window.agent.installUpdate(): Promise<void>', summary: 'Downloads, restarts to install, or (dev builds only) opens the release page, depending on the state.', source: 'src/shared/ipc.ts#L126' },
        ],
      },
      {
        title: 'Events (main → renderer)',
        intro: 'Each `on…` returns an unsubscribe function.',
        items: [
          { id: 'ipc-onstatuschanged', kind: 'event', name: 'onStatusChanged', channel: 'agent:status-changed', signature: 'window.agent.onStatusChanged(cb: () => void): () => void', summary: 'Pairings changed; call `getStatus()` again.', source: 'src/shared/ipc.ts#L127' },
          { id: 'ipc-onpairingprogress', kind: 'event', name: 'onPairingProgress', channel: 'agent:pairing-progress', signature: 'window.agent.onPairingProgress(cb: (p: PairingProgressView) => void): () => void', summary: 'Stages `looking_up`, `creating_keys`, `awaiting_confirmation`, `paired`.', source: 'src/shared/ipc.ts#L128' },
          { id: 'ipc-onpairprefill', kind: 'event', name: 'onPairPrefill', channel: 'agent:pair-prefill', signature: 'window.agent.onPairPrefill(cb: (p: { origin; code }) => void): () => void', summary: 'A pair link was opened; prefill the form.', source: 'src/shared/ipc.ts#L129' },
          { id: 'ipc-onjobstate', kind: 'event', name: 'onJobState', channel: 'agent:job-state', signature: 'window.agent.onJobState(cb: (s: JobState & { id }) => void): () => void', summary: 'Confirm-window updates for a job.', returns: `| { state: 'waiting_for_os_prompt' }
| { state: 'completed' }
| { state: 'rejected'; reason }
| { state: 'failed'; error }`, source: 'src/shared/ipc.ts#L130' },
          { id: 'ipc-onupdatechanged', kind: 'event', name: 'onUpdateChanged', channel: 'agent:update-changed', signature: 'window.agent.onUpdateChanged(cb: (u: UpdateView) => void): () => void', summary: 'The update state changed.', source: 'src/shared/ipc.ts#L131' },
        ],
      },
    ],
  },

  // ───────────────────────────── Config ─────────────────────────────
  {
    id: 'config',
    title: 'Configuration',
    intro: 'Environment variables read by the agent, the native module and the build.',
    groups: [
      {
        title: 'Environment variables',
        items: [
          {
            id: 'env-vars',
            kind: 'constant',
            name: 'Runtime and build switches',
            summary: 'Installer options are in [Installation](#/installation/options).',
            table: [
              ['KUKUX_KEYSTORE_BACKEND=software', 'Force software keys (CI runners have no Secure Enclave, TPM or Hello).'],
              ['KUKUX_KEYSTORE_DEBUG=1', 'Log why hardware key creation fell back (macOS).'],
              ['KUKUX_BIOMETRY_ONLY=1', 'macOS: require biometrics (`BiometryCurrentSet`) instead of biometrics-or-password.'],
              ['KUKUX_SIGNED_BUILD=true', 'Set by the release workflow for signed builds; baked into `SIGNED_BUILD`.'],
              ['ELECTRON_RUN_AS_NODE', 'Unset it when running `npm run dev` from VS Code’s terminal, or Electron starts as plain Node.'],
            ],
            source: 'README.md',
          },
        ],
      },
    ],
  },
];
