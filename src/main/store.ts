// Paired servers and agent tokens (desktop-agent-plan.md §7.3).
//
// servers.json holds public metadata (origin, ids, key ids). Agent tokens are
// stored separately, encrypted with Electron safeStorage (Keychain / DPAPI).
// safeStorage is fine for bearer tokens, never for signing keys: those stay
// in the Secure Enclave / TPM.
//
// One entry per server id: a computer holds at most one signature per app
// (multi-app-pairing-plan.md §1.1).
//
// pending-revokes.json holds unpairs the server hasn't acknowledged yet
// (§7.3), with their token sealed the same way. Their identity (signing) key
// is already gone; only the session key is kept, to authenticate the revoke.
//
// trust-anchors.json pins each paired app's signing CA (GET
// /signature/trust/ca.pem), fetched the first time a PDF is verified against
// it. "Verify a PDF" trusts only this stored copy, so a file can never bring
// its own root. Pairing again re-pins it; unpairing the last pairing at that
// origin drops it.
import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { DeviceType } from './device-type';
import type { Algorithm, KeySource, Protection } from './keystore';

export interface PairedServer {
  id: string;
  name: string;
  origin: string;
  salt: string;
  userId: string;
  userName: string;
  deviceUuid: string;
  deviceLabel: string;
  identityKeyId: string;
  sessionKeyId: string;
  algorithm: Algorithm;
  protection: Protection;
  userPresence: boolean;
  pairedAt: string;
  /** Optional: pairings made before device types existed are filled in at start-up. */
  deviceType?: DeviceType;
  /** Missing = 'platform': pairings made before certificates (pkcs12-key-storage-plan.md §6.4). */
  keySource?: KeySource;
  /** keySource 'pkcs12': the imported certificate whose key is identityKeyId. */
  certificateId?: string;
}

export function keySourceOf(server: Pick<PairedServer, 'keySource'>): KeySource {
  return server.keySource ?? 'platform';
}

/**
 * The keys that belong to this pairing alone, so unpairing may delete them
 * (pkcs12-key-storage-plan.md §6.5). A certificate's key is shared by every
 * pairing made with it and is deleted only with the certificate.
 */
export function ownedKeyIds(server: Pick<PairedServer, 'keySource' | 'identityKeyId' | 'sessionKeyId'>): string[] {
  return keySourceOf(server) === 'pkcs12' ? [server.sessionKeyId] : [server.identityKeyId, server.sessionKeyId];
}

/** An unpair whose server-side revoke failed, retried until it succeeds (§7.3). */
export interface PendingRevoke {
  serverId: string;
  origin: string;
  userId: string;
  deviceUuid: string;
  sessionKeyId: string;
  queuedAt: string;
  /** For the status window. Revokes queued by older versions lack it. */
  serverName?: string;
}

export interface TokenCipher {
  isAvailable(): boolean;
  encrypt(plain: string): Buffer;
  decrypt(cipher: Buffer): string;
}

/** Agent tokens sealed to the Secure Enclave (free macOS builds, no keychain). */
export function sealedTokenCipher(sealer: {
  sealingAvailable(): boolean;
  sealData(plain: Buffer): Buffer;
  openData(sealed: Buffer): Buffer;
}): TokenCipher {
  return {
    isAvailable: () => sealer.sealingAvailable(),
    encrypt: (plain) => sealer.sealData(Buffer.from(plain, 'utf8')),
    decrypt: (cipher) => sealer.openData(cipher).toString('utf8'),
  };
}

interface ServersFile {
  version: 1;
  servers: PairedServer[];
}

type TokensFile = Record<string, string>;

/** A paired app's CA certificate (PEM), by origin. Public data. */
export interface TrustAnchor {
  pem: string;
  pinnedAt: string;
}

interface TrustAnchorsFile {
  version: 1;
  anchors: Record<string, TrustAnchor>;
}

interface RevokesFile {
  version: 1;
  revokes: Array<PendingRevoke & { token: string }>;
}

export class Store {
  private servers: PairedServer[] = [];
  private tokens: TokensFile = {};
  private revokes: Array<PendingRevoke & { token: string }> = [];
  private anchors: Record<string, TrustAnchor> = {};
  private loaded = false;

  constructor(
    private readonly dir: string,
    private readonly cipher: TokenCipher,
  ) {}

  async load(): Promise<void> {
    const servers = await readJson<ServersFile>(this.file('servers.json'));
    this.servers = servers?.version === 1 && Array.isArray(servers.servers) ? servers.servers : [];
    this.tokens = (await readJson<TokensFile>(this.file('tokens.json'))) ?? {};
    const revokes = await readJson<RevokesFile>(this.file('pending-revokes.json'));
    this.revokes = revokes?.version === 1 && Array.isArray(revokes.revokes) ? revokes.revokes : [];
    const anchors = await readJson<TrustAnchorsFile>(this.file('trust-anchors.json'));
    this.anchors = anchors?.version === 1 && anchors.anchors && typeof anchors.anchors === 'object' ? anchors.anchors : {};
    this.loaded = true;
  }

  list(): PairedServer[] {
    this.assertLoaded();
    return this.servers.map((s) => ({ ...s }));
  }

  get(serverId: string): PairedServer | null {
    this.assertLoaded();
    const found = this.servers.find((s) => s.id === serverId);
    return found ? { ...found } : null;
  }

  findByOrigin(origin: string): PairedServer | null {
    this.assertLoaded();
    const found = this.servers.find((s) => s.origin === origin);
    return found ? { ...found } : null;
  }

  async save(server: PairedServer, token: string): Promise<void> {
    this.assertLoaded();
    if (!this.cipher.isAvailable()) {
      throw new Error('secure storage is unavailable, so the agent token cannot be stored safely');
    }
    this.servers = [...this.servers.filter((s) => s.id !== server.id), { ...server }];
    this.tokens = { ...this.tokens, [server.id]: this.cipher.encrypt(token).toString('base64') };
    // A new pairing is a new trust decision: pin the CA again on next use.
    this.anchors = withoutKey(this.anchors, server.origin);
    await this.flush();
  }

  /** Rewrites a pairing's metadata, keeping its token. */
  async update(server: PairedServer): Promise<void> {
    this.assertLoaded();
    if (!this.servers.some((s) => s.id === server.id)) throw new Error(`no pairing for ${server.id}`);
    this.servers = this.servers.map((s) => (s.id === server.id ? { ...server } : s));
    await this.flush();
  }

  token(serverId: string): string | null {
    this.assertLoaded();
    const encrypted = this.tokens[serverId];
    if (!encrypted) return null;
    try {
      return this.cipher.decrypt(Buffer.from(encrypted, 'base64'));
    } catch {
      return null;
    }
  }

  async remove(serverId: string): Promise<void> {
    this.assertLoaded();
    const origin = this.servers.find((s) => s.id === serverId)?.origin;
    this.servers = this.servers.filter((s) => s.id !== serverId);
    const { [serverId]: _removed, ...rest } = this.tokens;
    this.tokens = rest;
    if (origin && !this.servers.some((s) => s.origin === origin)) this.anchors = withoutKey(this.anchors, origin);
    await this.flush();
  }

  // ── Trust anchors for "Verify a PDF" ──

  trustAnchor(origin: string): TrustAnchor | null {
    this.assertLoaded();
    const found = Object.hasOwn(this.anchors, origin) ? this.anchors[origin] : undefined;
    return found && typeof found.pem === 'string' ? { ...found } : null;
  }

  /** Pins a CA for a paired origin. Never replaces an existing pin, and ignores origins nothing is paired with. */
  async pinTrustAnchor(origin: string, pem: string): Promise<TrustAnchor | null> {
    this.assertLoaded();
    const existing = this.trustAnchor(origin);
    if (existing) return existing;
    if (!this.servers.some((s) => s.origin === origin)) return null;
    const anchor: TrustAnchor = { pem, pinnedAt: new Date().toISOString() };
    this.anchors = { ...this.anchors, [origin]: anchor };
    await this.flush();
    return { ...anchor };
  }

  // ── Pending revokes (§7.3) ──

  pendingRevokes(serverId?: string): PendingRevoke[] {
    this.assertLoaded();
    return this.revokes
      .filter((r) => serverId === undefined || r.serverId === serverId)
      .map(({ token: _token, ...r }) => ({ ...r }));
  }

  revokeToken(deviceUuid: string): string | null {
    this.assertLoaded();
    const found = this.revokes.find((r) => r.deviceUuid === deviceUuid);
    if (!found) return null;
    try {
      return this.cipher.decrypt(Buffer.from(found.token, 'base64'));
    } catch {
      return null;
    }
  }

  /** Moves a pairing to the revoke queue: it stops being a pairing at once, but its token is kept for the retry. */
  async queueRevoke(revoke: PendingRevoke, token: string): Promise<void> {
    this.assertLoaded();
    if (!this.cipher.isAvailable()) {
      throw new Error('secure storage is unavailable, so the agent token cannot be stored safely');
    }
    this.revokes = [
      ...this.revokes.filter((r) => r.deviceUuid !== revoke.deviceUuid),
      { ...revoke, token: this.cipher.encrypt(token).toString('base64') },
    ];
    await this.flush();
  }

  async dropRevoke(deviceUuid: string): Promise<void> {
    this.assertLoaded();
    this.revokes = this.revokes.filter((r) => r.deviceUuid !== deviceUuid);
    await this.flush();
  }

  private async flush(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    await writeJsonAtomic(this.file('servers.json'), { version: 1, servers: this.servers } satisfies ServersFile);
    await writeJsonAtomic(this.file('tokens.json'), this.tokens);
    await writeJsonAtomic(this.file('pending-revokes.json'), { version: 1, revokes: this.revokes } satisfies RevokesFile);
    await writeJsonAtomic(this.file('trust-anchors.json'), { version: 1, anchors: this.anchors } satisfies TrustAnchorsFile);
  }

  private file(name: string): string {
    return path.join(this.dir, name);
  }

  private assertLoaded(): void {
    if (!this.loaded) throw new Error('Store.load() must be called first');
  }
}

function withoutKey<T>(record: Record<string, T>, key: string): Record<string, T> {
  if (!Object.hasOwn(record, key)) return record;
  const { [key]: _removed, ...rest } = record;
  return rest;
}

export async function readJson<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

export async function writeJsonAtomic(file: string, data: unknown): Promise<void> {
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  await fs.rename(tmp, file);
}
