// HTTPS client for /signature/agent/* (desktop-agent-plan.md §8; docs: #/how-the-api-works).
//
// Every request goes to the one origin the client was built for; redirects
// are refused, so a compromised path can't bounce the agent elsewhere.
// Authenticated calls carry the bearer token plus an X-Agent-Proof signed by
// the session key, so a leaked token alone is useless (§8.4).
import { randomBytes } from 'node:crypto';

import { canonicalMessage, requestPayloadHash } from './canonical';
import type { DeviceType } from './device-type';
import { normalizeOrigin, type OriginPolicy } from './protocol';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface ServerInfo {
  id: string;
  name: string;
  origin: string;
  /** Per-server salt for the hardware id hash (§10.4). */
  salt: string;
}

export interface PairingLookup {
  pairing: string;
  nonce: string;
  user_id: string;
  user_name?: string;
  server: ServerInfo;
  require_presence: boolean;
  /** Device types this server refuses to pair (multi-app-pairing-plan.md §4.6). Older servers omit it. */
  blocked_device_types?: string[];
  /** The account's paired computer for this app (one-computer-per-account-plan.md §4.1). Older servers omit it. */
  agent_device?: AccountDevice | null;
  /** Where the account's signing devices are managed on the web. Older servers omit it. */
  devices_url?: string;
  expires_at: string;
}

/** The computer an account is already paired with. Its hash only tells whether it's this computer. */
export interface AccountDevice {
  uuid: string;
  label: string;
  device_type?: string;
  hardware_id_hash?: string | null;
}

export interface PairingClaim {
  user_code: string;
  algorithm: 'ES256' | 'RS256';
  identity_public_key: string;
  session_public_key: string;
  protection: 'secure_enclave' | 'tpm' | 'software';
  user_presence: boolean;
  attestation: { format: string; statement: string; chain: string[] } | null;
  device: {
    platform: string;
    os_version: string;
    model: string;
    model_identifier: string;
    form_factor: string;
    label: string;
    /** null when the firmware has no usable hardware uuid: never the hash of "" (§3). */
    hardware_id_hash: string | null;
    device_type: DeviceType;
    chassis_type: number | null;
    virtual: boolean;
  };
  agent_version: string;
  proof: string;
}

/** The server's device for this computer and user, which a re-pair updates (§7.2). */
export interface ExistingDevice {
  uuid: string;
  label: string;
  device_type?: string;
}

export interface PairingClaimResult {
  status: string;
  poll_secret: string;
  existing_device?: ExistingDevice | null;
}

export type PairingStatus =
  | { status: 'awaiting_confirmation' }
  | {
      status: 'confirmed';
      device: { uuid: string; label: string; device_type?: string };
      token: string;
      /** true when the server updated an existing device instead of adding one. */
      rebound?: boolean;
    }
  | { status: 'rejected' | 'expired' };

export interface AgentJob {
  uuid: string;
  purpose: string;
  status: string;
  nonce: string;
  user_id: string;
  payload_hash: string;
  document: { title: string };
  signer: { name: string };
  expires_at: string;
}

export interface OtherDevice {
  uuid: string;
  label: string;
  device_type?: string;
  last_used_at?: string | null;
}

export interface AgentStatus {
  device: { uuid: string; label: string; status: string };
  user: { id: string; name: string };
  /** The same account's other active signing devices (§7.4). Older servers omit it. */
  other_devices?: OtherDevice[];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }

  /** 426: the server's `min_version` is newer than this agent. */
  get outdated(): boolean {
    return this.status === 426 || this.code === 'agent_outdated';
  }

  /** 401 on an authenticated call: token revoked or device unpaired on the web. */
  get unauthorized(): boolean {
    return this.status === 401;
  }
}

export interface Credentials {
  token: string;
  userId: string;
  /** Signs with the session key (no user prompt). */
  signWithSessionKey(message: Buffer): Promise<Buffer>;
}

export interface ApiOptions extends OriginPolicy {
  origin: string;
  agentVersion: string;
  fetch?: FetchLike;
  timeoutMs?: number;
  /** For tests. */
  now?: () => number;
}

const BASE = '/signature/agent';

export class AgentApi {
  readonly origin: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly now: () => number;

  constructor(private readonly options: ApiOptions) {
    const origin = normalizeOrigin(options.origin, options);
    if (!origin) throw new Error(`refusing non-HTTPS or malformed origin: ${options.origin}`);
    this.origin = origin;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.now = options.now ?? Date.now;
  }

  // ── Pairing (unauthenticated: the user code and proofs carry the trust) ──

  lookupPairing(userCode: string): Promise<PairingLookup> {
    return this.request('POST', `${BASE}/pairings/lookup`, { user_code: userCode });
  }

  claimPairing(pairing: string, claim: PairingClaim): Promise<PairingClaimResult> {
    return this.request('POST', `${BASE}/pairings/${encodeURIComponent(pairing)}/claim`, claim);
  }

  pollPairing(pairing: string, pollSecret: string): Promise<PairingStatus> {
    return this.request('POST', `${BASE}/pairings/${encodeURIComponent(pairing)}/poll`, { poll_secret: pollSecret });
  }

  // ── Authenticated agent calls ──

  status(creds: Credentials): Promise<AgentStatus> {
    return this.request('GET', `${BASE}/status`, undefined, creds);
  }

  /** Consumes the one-time link token and binds the job to this device. */
  claimJob(creds: Credentials, jobId: string, linkToken: string): Promise<AgentJob> {
    return this.request('POST', `${BASE}/jobs/${encodeURIComponent(jobId)}/claim`, { link_token: linkToken }, creds);
  }

  completeJob(creds: Credentials, jobId: string, proof: string): Promise<{ status: string }> {
    return this.request('POST', `${BASE}/jobs/${encodeURIComponent(jobId)}/complete`, { proof }, creds);
  }

  rejectJob(creds: Credentials, jobId: string, reason: string): Promise<{ status: string }> {
    return this.request('POST', `${BASE}/jobs/${encodeURIComponent(jobId)}/reject`, { reason }, creds);
  }

  /** Revokes this device's token on the server. */
  unpair(creds: Credentials): Promise<void> {
    return this.request('DELETE', `${BASE}/device`, undefined, creds);
  }

  private async request<T>(method: string, path: string, payload?: unknown, creds?: Credentials): Promise<T> {
    const url = new URL(path, this.origin);
    if (url.origin !== this.origin) throw new Error('request escaped the pinned origin');

    const body = payload === undefined ? '' : JSON.stringify(payload);
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'X-Agent-Version': this.options.agentVersion,
    };
    if (body) headers['Content-Type'] = 'application/json';

    if (creds) {
      const timestamp = String(Math.floor(this.now() / 1000));
      const nonce = randomBytes(16).toString('base64url');
      const pathWithQuery = url.pathname + url.search;
      const message = canonicalMessage(
        'request',
        nonce,
        creds.userId,
        requestPayloadHash(method, pathWithQuery, body, timestamp),
      );
      const proof = await creds.signWithSessionKey(Buffer.from(message, 'utf8'));
      headers.Authorization = `Bearer ${creds.token}`;
      headers['X-Agent-Timestamp'] = timestamp;
      headers['X-Agent-Nonce'] = nonce;
      headers['X-Agent-Proof'] = proof.toString('base64');
    }

    const response = await this.fetchImpl(url.toString(), {
      method,
      headers,
      body: body || undefined,
      redirect: 'error',
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    const text = await response.text();
    let data: unknown = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        throw new ApiError(response.status, 'invalid_response', 'the server returned a non-JSON response');
      }
    }

    if (!response.ok) {
      const error = (data as { error?: { code?: string; message?: string } } | null)?.error ?? {};
      const code = error.code ?? `http_${response.status}`;
      let message = error.message ?? `request failed with HTTP ${response.status}`;
      if (code === 'stale_request') message += " Check this computer's clock.";
      throw new ApiError(
        response.status,
        code,
        message,
        (data as Record<string, unknown>) ?? {},
      );
    }
    return data as T;
  }
}
