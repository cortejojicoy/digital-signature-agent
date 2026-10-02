// In-memory implementation of the server side of the agent API
// (https://cortejojicoy.github.io/digital-signature-agent/#/how-the-api-works).
//
// Used by the integration tests, and runnable on its own as the "local test
// server" for trying the real Electron app (npm run mock-server). It is also
// a reference for the package's Laravel implementation: every check the
// package must make is here (proof verification, single-use link tokens,
// request-proof replay and staleness, min_version, device binding, one
// device per computer and app, blocked device types).
//
// Self-contained (node: imports only) so Node can run it directly with type
// stripping.
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { networkInterfaces } from 'node:os';

export interface MockUser {
  id: string;
  name: string;
}

export interface MockServerOptions {
  port?: number;
  /** Bind to every interface and advertise this machine's LAN address, so an agent on another machine can reach it. */
  lan?: boolean;
  serverId?: string;
  serverName?: string;
  minVersion?: string;
  requirePresence?: boolean;
  /** Mirrors signature.devices.agent.blocked_device_types; virtual machines by default. */
  blockedDeviceTypes?: string[];
  users?: MockUser[];
  now?: () => number;
}

interface Pairing {
  uuid: string;
  userId: string;
  userCodeHash: string;
  nonce: string;
  status: 'pending' | 'awaiting_confirmation' | 'confirmed' | 'rejected' | 'expired';
  expiresAt: number;
  pollSecret?: string;
  claim?: Record<string, unknown>;
  deviceUuid?: string;
  tokenIssued?: boolean;
  /** Same computer, same user: confirming updates this device instead of adding one. */
  replacesDeviceUuid?: string;
}

export interface Device {
  uuid: string;
  userId: string;
  label: string;
  algorithm: 'ES256' | 'RS256';
  identityKey: string; // base64 SPKI
  sessionKey: string; // base64 SPKI
  protection: string;
  userPresence: boolean;
  attested: boolean;
  formFactor: string;
  model: string;
  hardwareIdHash: string | null;
  deviceType: string;
  virtual: boolean;
  agentVersion: string;
  revoked: boolean;
  rebound: boolean;
}

export interface Job {
  uuid: string;
  userId: string;
  deviceUuid: string | null;
  purpose: 'sign_receipt';
  title: string;
  payloadHash: string;
  nonce: string;
  linkTokenHash: string;
  status: 'pending' | 'claimed' | 'completed' | 'rejected' | 'expired';
  result: Record<string, unknown> | null;
  expiresAt: number;
}

const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
const b64url = (bytes: number) => randomBytes(bytes).toString('base64url');
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly extra: Record<string, unknown>;

  constructor(status: number, code: string, message: string, extra: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export function canonical(purpose: string, nonce: string, userId: string, payloadHash: string): string {
  return `v1|${purpose}|${nonce}|${userId}|${payloadHash}`;
}

export function verifyProof(algorithm: string, spkiB64: string, message: string, signatureB64: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(spkiB64, 'base64'), format: 'der', type: 'spki' });
    const data = Buffer.from(message, 'utf8');
    const sig = Buffer.from(signatureB64, 'base64');
    if (algorithm === 'ES256') return verify('sha256', data, { key, dsaEncoding: 'der' }, sig);
    if (algorithm === 'RS256') return verify('sha256', data, key, sig);
    return false;
  } catch {
    return false;
  }
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

function normalizeCode(code: string): string {
  return String(code).toUpperCase().replace(/[\s-]/g, '');
}

export class MockSigningServer {
  origin = '';
  readonly serverId: string;
  readonly serverName: string;
  readonly salt = b64url(16);
  minVersion: string;
  requirePresence: boolean;
  blockedDeviceTypes: string[];
  /** The next DELETE /device answers 503, as if the server were unreachable. */
  failNextUnpair = false;
  readonly users: MockUser[];
  readonly pairings = new Map<string, Pairing>();
  readonly devices = new Map<string, Device>();
  readonly tokens = new Map<string, string>(); // sha256(token) → device uuid
  readonly jobs = new Map<string, Job>();
  readonly seenRequestNonces = new Set<string>();
  private readonly http = createServer((req, res) => void this.route(req, res));
  private readonly now: () => number;
  private readonly options: MockServerOptions;

  constructor(options: MockServerOptions = {}) {
    this.options = options;
    this.serverId = options.serverId ?? 'test-server';
    this.serverName = options.serverName ?? 'Test Signing App';
    this.minVersion = options.minVersion ?? '0.0.0';
    this.requirePresence = options.requirePresence ?? false;
    this.blockedDeviceTypes = options.blockedDeviceTypes ?? ['virtual_machine'];
    this.users = options.users ?? [{ id: '42', name: 'Juan dela Cruz' }];
    this.now = options.now ?? Date.now;
  }

  async listen(): Promise<string> {
    const lan = this.options.lan ? lanAddress() : null;
    if (this.options.lan && !lan) throw new Error('no LAN IPv4 address found; is this machine on a network?');
    await new Promise<void>((resolve) => this.http.listen(this.options.port ?? 0, lan ? '0.0.0.0' : '127.0.0.1', resolve));
    const { port } = this.http.address() as AddressInfo;
    this.origin = `http://${lan ?? '127.0.0.1'}:${port}`;
    return this.origin;
  }

  close(): Promise<void> {
    return new Promise((resolve) => this.http.close(() => resolve()));
  }

  // ── What the web app does (Filament side) ──

  startPairing(userId = this.users[0].id): { uuid: string; userCode: string; link: string } {
    let code = '';
    for (const byte of randomBytes(8)) code += ALPHABET[byte % ALPHABET.length];
    const userCode = `${code.slice(0, 4)}-${code.slice(4)}`;
    const pairing: Pairing = {
      uuid: randomUUID(),
      userId,
      userCodeHash: sha256(normalizeCode(userCode)),
      nonce: b64url(32),
      status: 'pending',
      expiresAt: this.now() + 600_000,
    };
    this.pairings.set(pairing.uuid, pairing);
    const link = `kukuxsign://pair?o=${encodeURIComponent(this.origin)}&c=${userCode}`;
    return { uuid: pairing.uuid, userCode, link };
  }

  /** The second confirmation: the logged-in user approves this machine on the web. */
  confirmPairing(uuid: string, approve = true): Device | null {
    const p = this.pairings.get(uuid);
    if (!p || p.status !== 'awaiting_confirmation' || !p.claim) throw new Error('pairing is not awaiting confirmation');
    if (!approve) {
      p.status = 'rejected';
      return null;
    }
    const c = p.claim as Record<string, any>;
    // Re-check under "the lock": another pairing may have taken this computer meanwhile.
    const holder = this.activeDeviceFor(c.device?.hardware_id_hash ?? null);
    if (holder && holder.userId !== p.userId) throw new Error('machine_already_paired');

    const keys = {
      algorithm: c.algorithm,
      identityKey: c.identity_public_key,
      sessionKey: c.session_public_key,
      protection: c.protection,
      userPresence: !!c.user_presence,
      attested: false, // phase 5: verify c.attestation against Microsoft TPM roots
      formFactor: c.device?.form_factor,
      model: c.device?.model,
      deviceType: String(c.device?.device_type ?? 'other'),
      virtual: !!c.device?.virtual,
      agentVersion: c.agent_version,
    };
    const existing = holder && holder.userId === p.userId ? holder : null;
    if (existing) {
      // Rebind: same uuid and label, new keys; the old token stops working.
      Object.assign(existing, keys, { rebound: true });
      for (const [hash, uuid] of this.tokens) if (uuid === existing.uuid) this.tokens.delete(hash);
      p.status = 'confirmed';
      p.deviceUuid = existing.uuid;
      p.replacesDeviceUuid = existing.uuid;
      return existing;
    }

    const device: Device = {
      uuid: randomUUID(),
      userId: p.userId,
      label: String(c.device?.label ?? 'Computer'),
      hardwareIdHash: c.device?.hardware_id_hash ?? null,
      revoked: false,
      rebound: false,
      ...keys,
    };
    this.devices.set(device.uuid, device);
    p.status = 'confirmed';
    p.deviceUuid = device.uuid;
    return device;
  }

  /** An admin's "Release computer" (§7.3). */
  releaseDevice(uuid: string): void {
    const device = this.devices.get(uuid);
    if (device) device.revoked = true;
    for (const [hash, owner] of this.tokens) if (owner === uuid) this.tokens.delete(hash);
  }

  /** The active agent device on this computer for this app, whoever owns it. */
  private activeDeviceFor(hardwareIdHash: string | null): Device | undefined {
    if (!hardwareIdHash) return undefined;
    return [...this.devices.values()].find((d) => !d.revoked && d.hardwareIdHash === hardwareIdHash);
  }

  createJob(title: string, documentHash: string, userId = this.users[0].id): { uuid: string; linkToken: string; link: string } {
    const linkToken = b64url(32);
    const job: Job = {
      uuid: randomUUID(),
      userId,
      deviceUuid: null,
      purpose: 'sign_receipt',
      title,
      payloadHash: documentHash,
      nonce: b64url(32),
      linkTokenHash: sha256(linkToken),
      status: 'pending',
      result: null,
      expiresAt: this.now() + 300_000,
    };
    this.jobs.set(job.uuid, job);
    const link = `kukuxsign://job/${job.uuid}?t=${linkToken}&s=${this.serverId}`;
    return { uuid: job.uuid, linkToken, link };
  }

  // ── HTTP ──

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const body = await readBody(req);
      const url = new URL(req.url ?? '/', this.origin);
      const method = req.method ?? 'GET';
      const json = body ? JSON.parse(body) : {};
      const path = url.pathname;
      let m: RegExpExecArray | null;

      const version = String(req.headers['x-agent-version'] ?? '0.0.0');
      if (path.startsWith('/signature/agent/') && compareVersions(version, this.minVersion) < 0) {
        throw new HttpError(426, 'agent_outdated', `Kukux Sign Agent ${this.minVersion} or newer is required.`, {
          min_version: this.minVersion,
        });
      }

      // Development helpers for driving the real app by hand (npm run mock-server).
      if (method === 'POST' && path === '/__dev/pairings') return send(res, 200, this.startPairing());
      if (method === 'POST' && (m = /^\/__dev\/pairings\/([^/]+)\/confirm$/.exec(path))) {
        return send(res, 200, { device: this.confirmPairing(m[1]) });
      }
      if (method === 'POST' && path === '/__dev/jobs') {
        return send(res, 200, this.createJob(json.title ?? 'Accomplishment Report – Sept', json.document_hash ?? sha256(b64url(16))));
      }
      if (method === 'GET' && (m = /^\/__dev\/jobs\/([^/]+)$/.exec(path))) return send(res, 200, this.jobs.get(m[1]) ?? null);

      if (method === 'POST' && path === '/signature/agent/pairings/lookup') return send(res, 200, this.lookup(json));
      if (method === 'POST' && (m = /^\/signature\/agent\/pairings\/([^/]+)\/claim$/.exec(path))) {
        return send(res, 200, this.claim(m[1], json));
      }
      if (method === 'POST' && (m = /^\/signature\/agent\/pairings\/([^/]+)\/poll$/.exec(path))) {
        return send(res, 200, this.poll(m[1], json));
      }

      const device = this.authenticate(req, method, url.pathname + url.search, body);
      if (method === 'GET' && path === '/signature/agent/status') {
        const user = this.users.find((u) => u.id === device.userId)!;
        const others = [...this.devices.values()]
          .filter((d) => d.userId === device.userId && d.uuid !== device.uuid && !d.revoked)
          .map((d) => ({ uuid: d.uuid, label: d.label, device_type: d.deviceType, last_used_at: null }));
        return send(res, 200, { device: { uuid: device.uuid, label: device.label, status: 'active' }, user, other_devices: others });
      }
      if (method === 'DELETE' && path === '/signature/agent/device') {
        if (this.failNextUnpair) {
          this.failNextUnpair = false;
          throw new HttpError(503, 'unavailable', 'Service unavailable.');
        }
        device.revoked = true;
        return send(res, 204, null);
      }
      if (method === 'POST' && (m = /^\/signature\/agent\/jobs\/([^/]+)\/claim$/.exec(path))) {
        return send(res, 200, this.claimJob(device, m[1], json));
      }
      if (method === 'POST' && (m = /^\/signature\/agent\/jobs\/([^/]+)\/complete$/.exec(path))) {
        return send(res, 200, this.completeJob(device, m[1], json));
      }
      if (method === 'POST' && (m = /^\/signature\/agent\/jobs\/([^/]+)\/reject$/.exec(path))) {
        return send(res, 200, this.rejectJob(device, m[1], json));
      }
      throw new HttpError(404, 'not_found', 'Not found.');
    } catch (err) {
      if (err instanceof HttpError) return send(res, err.status, { error: { code: err.code, message: err.message }, ...err.extra });
      return send(res, 500, { error: { code: 'server_error', message: String(err) } });
    }
  }

  private lookup(json: { user_code?: string }) {
    const hash = sha256(normalizeCode(json.user_code ?? ''));
    const p = [...this.pairings.values()].find((x) => x.userCodeHash === hash && x.status === 'pending');
    if (!p || p.expiresAt < this.now()) throw new HttpError(404, 'invalid_code', 'That code is invalid or has expired.');
    const user = this.users.find((u) => u.id === p.userId)!;
    return {
      pairing: p.uuid,
      nonce: p.nonce,
      user_id: p.userId,
      user_name: user.name,
      server: { id: this.serverId, name: this.serverName, origin: this.origin, salt: this.salt },
      require_presence: this.requirePresence,
      blocked_device_types: this.blockedDeviceTypes,
      expires_at: new Date(p.expiresAt).toISOString(),
    };
  }

  private claim(uuid: string, c: Record<string, any>) {
    const p = this.pairings.get(uuid);
    if (!p || p.status !== 'pending' || p.expiresAt < this.now()) throw new HttpError(404, 'invalid_pairing', 'Pairing not found.');
    if (sha256(normalizeCode(c.user_code ?? '')) !== p.userCodeHash) throw new HttpError(403, 'invalid_code', 'Wrong code.');
    if (c.algorithm !== 'ES256' && c.algorithm !== 'RS256') throw new HttpError(422, 'invalid_algorithm', 'Unsupported algorithm.');
    const identity = Buffer.from(String(c.identity_public_key ?? ''), 'base64');
    const session = Buffer.from(String(c.session_public_key ?? ''), 'base64');
    const message = canonical('register_agent', p.nonce, p.userId, sha256(Buffer.concat([identity, session])));
    if (!verifyProof(c.algorithm, c.identity_public_key, message, c.proof)) {
      throw new HttpError(422, 'invalid_proof', 'The registration proof did not verify.');
    }
    if (this.requirePresence && !c.user_presence) {
      throw new HttpError(422, 'presence_required', 'This server requires Touch ID or Windows Hello.');
    }
    const type = String(c.device?.device_type ?? 'other');
    if (this.blockedDeviceTypes.includes(type) || (c.device?.virtual && this.blockedDeviceTypes.includes('virtual_machine'))) {
      throw new HttpError(422, 'device_type_not_allowed', 'This kind of device is not allowed to pair.');
    }
    // One active device per computer and app (§7.2). The error never says who holds it.
    const holder = this.activeDeviceFor(c.device?.hardware_id_hash ?? null);
    if (holder && holder.userId !== p.userId) {
      throw new HttpError(409, 'machine_already_paired', 'This computer is already paired with another account.');
    }
    p.status = 'awaiting_confirmation';
    p.claim = c;
    p.pollSecret = b64url(32);
    return {
      status: p.status,
      poll_secret: p.pollSecret,
      existing_device: holder ? { uuid: holder.uuid, label: holder.label, device_type: holder.deviceType } : null,
    };
  }

  private poll(uuid: string, json: { poll_secret?: string }) {
    const p = this.pairings.get(uuid);
    if (!p || !p.pollSecret || json.poll_secret !== p.pollSecret) throw new HttpError(404, 'invalid_pairing', 'Pairing not found.');
    if (p.status === 'confirmed') {
      if (p.tokenIssued) throw new HttpError(409, 'token_already_issued', 'The token was already issued.');
      const token = b64url(32);
      this.tokens.set(sha256(token), p.deviceUuid!);
      p.tokenIssued = true;
      const d = this.devices.get(p.deviceUuid!)!;
      return {
        status: 'confirmed',
        device: { uuid: d.uuid, label: d.label, device_type: d.deviceType },
        token,
        rebound: p.replacesDeviceUuid !== undefined,
      };
    }
    if (p.expiresAt < this.now()) p.status = 'expired';
    return { status: p.status };
  }

  /** AuthenticateAgent middleware: bearer token + X-Agent-Proof (§8.4). */
  private authenticate(req: IncomingMessage, method: string, pathWithQuery: string, body: string): Device {
    const auth = String(req.headers.authorization ?? '');
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const deviceUuid = this.tokens.get(sha256(token));
    const device = deviceUuid ? this.devices.get(deviceUuid) : undefined;
    if (!device || device.revoked) throw new HttpError(401, 'unauthenticated', 'Invalid or revoked agent token.');

    const timestamp = String(req.headers['x-agent-timestamp'] ?? '');
    const nonce = String(req.headers['x-agent-nonce'] ?? '');
    const proof = String(req.headers['x-agent-proof'] ?? '');
    if (!/^\d+$/.test(timestamp) || Math.abs(this.now() / 1000 - Number(timestamp)) > 60) {
      throw new HttpError(401, 'stale_request', 'Request timestamp outside ±60 s.');
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce) || this.seenRequestNonces.has(`${device.uuid}:${nonce}`)) {
      throw new HttpError(401, 'replayed_request', 'Request nonce missing or reused.');
    }
    const payload = sha256(`${method}|${pathWithQuery}|${body}|${timestamp}`);
    if (!verifyProof('ES256', device.sessionKey, canonical('request', nonce, device.userId, payload), proof)) {
      throw new HttpError(401, 'invalid_request_proof', 'X-Agent-Proof did not verify.');
    }
    this.seenRequestNonces.add(`${device.uuid}:${nonce}`);
    return device;
  }

  private claimJob(device: Device, uuid: string, json: { link_token?: string }) {
    const job = this.jobs.get(uuid);
    if (!job || job.userId !== device.userId) throw new HttpError(404, 'job_not_found', 'Job not found.');
    if (job.expiresAt < this.now()) job.status = 'expired';
    if (job.status !== 'pending') throw new HttpError(409, 'job_unavailable', `Job is ${job.status}.`);
    if (sha256(String(json.link_token ?? '')) !== job.linkTokenHash) throw new HttpError(403, 'invalid_link_token', 'Invalid link.');
    job.status = 'claimed';
    job.deviceUuid = device.uuid;
    job.linkTokenHash = ''; // single use
    const user = this.users.find((u) => u.id === job.userId)!;
    return {
      uuid: job.uuid,
      purpose: job.purpose,
      status: job.status,
      nonce: job.nonce,
      user_id: job.userId,
      payload_hash: job.payloadHash,
      document: { title: job.title },
      signer: { name: user.name },
      expires_at: new Date(job.expiresAt).toISOString(),
    };
  }

  private completeJob(device: Device, uuid: string, json: { proof?: string }) {
    const job = this.jobs.get(uuid);
    if (!job || job.deviceUuid !== device.uuid || job.status !== 'claimed') {
      throw new HttpError(409, 'job_unavailable', 'Job is not claimed by this device.');
    }
    const message = canonical(job.purpose, job.nonce, job.userId, job.payloadHash);
    if (!verifyProof(device.algorithm, device.identityKey, message, String(json.proof ?? ''))) {
      throw new HttpError(422, 'invalid_proof', 'The signing proof did not verify.');
    }
    job.status = 'completed';
    job.result = { device_uuid: device.uuid, protection: device.protection, label: device.label };
    return { status: job.status };
  }

  private rejectJob(device: Device, uuid: string, json: { reason?: string }) {
    const job = this.jobs.get(uuid);
    if (!job || job.userId !== device.userId || (job.deviceUuid && job.deviceUuid !== device.uuid)) {
      throw new HttpError(404, 'job_not_found', 'Job not found.');
    }
    if (job.status === 'pending' || job.status === 'claimed') {
      job.status = 'rejected';
      job.result = { reason: json.reason ?? 'declined' };
    }
    return { status: job.status };
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function send(res: ServerResponse, status: number, data: unknown): void {
  if (status === 204) {
    res.writeHead(204).end();
    return;
  }
  res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(data));
}

/** First private (RFC 1918) IPv4 address, e.g. 192.168.1.20: the agent accepts plain http:// only for those. */
function lanAddress(): string | null {
  const isPrivate = (ip: string) => /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(ip);
  for (const addresses of Object.values(networkInterfaces())) {
    const found = addresses?.find((a) => a.family === 'IPv4' && !a.internal && isPrivate(a.address));
    if (found) return found.address;
  }
  return null;
}

// Standalone: node test/support/mock-server.ts [port] [--lan] [--allow-vm]
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const port = Number(args.find((a) => /^\d+$/.test(a)) ?? 8787);
  const server = new MockSigningServer({
    port,
    lan: args.includes('--lan'),
    // Virtual machines are refused by default, like the package.
    blockedDeviceTypes: args.includes('--allow-vm') ? [] : undefined,
  });
  const origin = await server.listen();
  const { uuid, userCode, link } = server.startPairing();
  console.log(`Mock signing server on ${origin}`);
  if (args.includes('--lan')) console.log('Reachable from this network: run the agent with `npm run dev` on the other machine.');
  console.log(`\nPair: enter ${origin} and code ${userCode}\n   or open ${link}`);
  console.log(`\nThen confirm on the "web":  curl -X POST ${origin}/__dev/pairings/${uuid}/confirm`);
  console.log(`Create a job:               curl -X POST ${origin}/__dev/jobs -d '{"title":"Accomplishment Report – Sept"}'`);
  console.log('                            then: open "<link from the response>"');
}
