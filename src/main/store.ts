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
import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { DeviceType } from './device-type';
import type { Algorithm, Protection } from './keystore';

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

interface RevokesFile {
  version: 1;
  revokes: Array<PendingRevoke & { token: string }>;
}

export class Store {
  private servers: PairedServer[] = [];
  private tokens: TokensFile = {};
  private revokes: Array<PendingRevoke & { token: string }> = [];
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
    this.servers = this.servers.filter((s) => s.id !== serverId);
    const { [serverId]: _removed, ...rest } = this.tokens;
    this.tokens = rest;
    await this.flush();
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
  }

  private file(name: string): string {
    return path.join(this.dir, name);
  }

  private assertLoaded(): void {
    if (!this.loaded) throw new Error('Store.load() must be called first');
  }
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
