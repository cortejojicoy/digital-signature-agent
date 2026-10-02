import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Store, type PairedServer } from '../src/main/store';
import { fakeCipher } from './support/fake-cipher';

const server: PairedServer = {
  id: 'test-server',
  name: 'Test Signing App',
  origin: 'https://sign.example.gov.ph',
  salt: 'salt',
  userId: '42',
  userName: 'Juan dela Cruz',
  deviceUuid: 'd',
  deviceLabel: 'MacBook Pro',
  identityKeyId: 'ds.x.identity',
  sessionKeyId: 'ds.x.session',
  algorithm: 'ES256',
  protection: 'secure_enclave',
  userPresence: true,
  pairedAt: '2026-09-30T00:00:00.000Z',
};

describe('Store', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'agent-store-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('round-trips servers and tokens across loads', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    await store.save(server, 'the-token');

    const again = new Store(dir, fakeCipher);
    await again.load();
    expect(again.get('test-server')).toEqual(server);
    expect(again.findByOrigin('https://sign.example.gov.ph')?.id).toBe('test-server');
    expect(again.token('test-server')).toBe('the-token');
  });

  it('never writes the token in plaintext', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    await store.save(server, 'the-token');
    const files = (await readFile(path.join(dir, 'servers.json'), 'utf8')) + (await readFile(path.join(dir, 'tokens.json'), 'utf8'));
    expect(files).not.toContain('the-token');
  });

  it('refuses to store a token without secure storage', async () => {
    const store = new Store(dir, { ...fakeCipher, isAvailable: () => false });
    await store.load();
    await expect(store.save(server, 't')).rejects.toThrow(/secure storage/);
    expect(store.list()).toEqual([]);
  });

  it('removes a server and its token', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    await store.save(server, 't');
    await store.remove('test-server');
    expect(store.get('test-server')).toBeNull();
    expect(store.token('test-server')).toBeNull();
  });

  it('loads a servers.json written before device types existed', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    await store.save(server, 't');
    const again = new Store(dir, fakeCipher);
    await again.load();
    expect(again.get('test-server')?.deviceType).toBeUndefined();
  });

  it('keeps one signature per app: three apps side by side, unpairing one leaves the others', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    for (const id of ['amp', 'sims', 'tks']) await store.save({ ...server, id, origin: `https://${id}.example.ph` }, `${id}-token`);
    await store.remove('sims');
    expect(store.list().map((s) => s.id)).toEqual(['amp', 'tks']);
    expect(store.token('amp')).toBe('amp-token');
    expect(store.token('tks')).toBe('tks-token');
  });

  it('updates a pairing without touching its token', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    await store.save(server, 'the-token');
    await store.update({ ...server, deviceType: 'macbook_pro' });
    expect(store.get('test-server')?.deviceType).toBe('macbook_pro');
    expect(store.token('test-server')).toBe('the-token');
    await expect(store.update({ ...server, id: 'nope' })).rejects.toThrow(/no pairing/);
  });

  it('queues revokes with their token sealed, across loads', async () => {
    const store = new Store(dir, fakeCipher);
    await store.load();
    const revoke = {
      serverId: 'test-server',
      origin: server.origin,
      userId: '42',
      deviceUuid: 'd',
      sessionKeyId: 'ds.x.session',
      queuedAt: '2026-10-02T00:00:00.000Z',
    };
    await store.queueRevoke(revoke, 'revoke-token');
    expect(await readFile(path.join(dir, 'pending-revokes.json'), 'utf8')).not.toContain('revoke-token');

    const again = new Store(dir, fakeCipher);
    await again.load();
    expect(again.pendingRevokes()).toEqual([revoke]);
    expect(again.pendingRevokes('other')).toEqual([]);
    expect(again.revokeToken('d')).toBe('revoke-token');

    await again.dropRevoke('d');
    expect(again.pendingRevokes()).toEqual([]);
    expect(again.revokeToken('d')).toBeNull();
  });
});
