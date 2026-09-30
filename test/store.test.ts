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
});
