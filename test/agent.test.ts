// End to end: the real Agent (pairing, jobs, API client, store) against the
// mock server over HTTP, with a software key store.
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Agent } from '../src/main/agent';
import { AgentApi } from '../src/main/api';
import type { ConfirmRequest } from '../src/main/jobs';
import { PairingError } from '../src/main/pairing';
import { Store } from '../src/main/store';
import { fakeCipher } from './support/fake-cipher';
import { MemoryKeyStore, type MemoryKeyStoreOptions } from './support/memory-keystore';
import { MockSigningServer, type MockServerOptions } from './support/mock-server';

const DOC_HASH = createHash('sha256').update('the exact PDF bytes').digest('hex');

interface Harness {
  server: MockSigningServer;
  keystore: MemoryKeyStore;
  store: Store;
  agent: Agent;
  confirms: ConfirmRequest[];
  approve: boolean;
  pairNow(): Promise<void>;
}

let dir: string;
let harness: Harness | null = null;

async function setup(opts: { server?: MockServerOptions; keystore?: MemoryKeyStoreOptions; agentVersion?: string } = {}): Promise<Harness> {
  const server = new MockSigningServer(opts.server);
  await server.listen();
  const keystore = new MemoryKeyStore(opts.keystore);
  const store = new Store(dir, fakeCipher);
  await store.load();

  const h: Harness = {
    server,
    keystore,
    store,
    confirms: [],
    approve: true,
    agent: null as unknown as Agent,
    async pairNow() {
      const { uuid, userCode } = server.startPairing();
      await h.agent.pair(server.origin, userCode, {
        onProgress: (p) => {
          if (p.stage === 'awaiting_confirmation') server.confirmPairing(uuid);
        },
      });
    },
  };
  h.agent = new Agent({
    keystore,
    store,
    agentVersion: opts.agentVersion ?? '1.0.0',
    allowInsecureLocalhost: true,
    pollIntervalMs: 5,
    confirm: async (request) => {
      h.confirms.push(request);
      return h.approve;
    },
  });
  harness = h;
  return h;
}

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'agent-e2e-'));
});
afterEach(async () => {
  await harness?.server.close();
  harness = null;
  await rm(dir, { recursive: true, force: true });
});

describe('pairing', () => {
  it('pairs after the web confirmation and stores the token encrypted', async () => {
    const h = await setup();
    await h.pairNow();

    const [paired] = h.store.list();
    expect(paired).toMatchObject({ id: 'test-server', origin: h.server.origin, userId: '42', protection: 'secure_enclave' });
    expect(h.store.token('test-server')).toBeTruthy();
    expect(h.keystore.keys.size).toBe(2);

    const device = [...h.server.devices.values()][0];
    expect(device).toMatchObject({ userPresence: true, formFactor: 'laptop', model: 'MacBook Pro', agentVersion: '1.0.0' });
    // Salted with this server's salt, so it can't be linked across servers.
    expect(device.hardwareIdHash).toBe(createHash('sha256').update(`${h.server.salt}TEST-UUID`).digest('hex'));
    // The registration proof required the OS prompt.
    expect(h.keystore.prompts).toEqual(['pair this computer with Test Signing App']);
  });

  it('pairs a Windows Hello-style RS256 identity key', async () => {
    const h = await setup({ keystore: { rsaIdentity: true, protection: 'tpm' } });
    await h.pairNow();
    expect(h.store.list()[0]).toMatchObject({ algorithm: 'RS256', protection: 'tpm' });
  });

  it('cleans up the keys when the web declines', async () => {
    const h = await setup();
    const { uuid, userCode } = h.server.startPairing();
    const err = await h.agent
      .pair(h.server.origin, userCode, {
        onProgress: (p) => {
          if (p.stage === 'awaiting_confirmation') h.server.confirmPairing(uuid, false);
        },
      })
      .catch((e) => e);
    expect(err).toBeInstanceOf(PairingError);
    expect(err.code).toBe('rejected');
    expect(h.keystore.keys.size).toBe(0);
    expect(h.store.list()).toEqual([]);
  });

  it('refuses early when the server requires presence and the key has none', async () => {
    const h = await setup({ server: { requirePresence: true }, keystore: { presence: false, protection: 'tpm' } });
    const { userCode } = h.server.startPairing();
    const err = await h.agent.pair(h.server.origin, userCode).catch((e) => e);
    expect(err.code).toBe('presence_unavailable');
    expect(h.keystore.keys.size).toBe(0);
  });

  it('rejects a wrong code and a malformed origin', async () => {
    const h = await setup();
    h.server.startPairing();
    await expect(h.agent.pair(h.server.origin, 'AAAA-BBBB')).rejects.toThrow(/invalid or has expired/);
    await expect(h.agent.pair('http://evil.test', 'AAAA-BBBB')).rejects.toThrow(/HTTPS/);
    expect(h.keystore.keys.size).toBe(0);
  });

  it('re-pairing replaces the old keys only after success', async () => {
    const h = await setup();
    await h.pairNow();
    const before = h.store.list()[0];
    await h.pairNow();
    const after = h.store.list()[0];
    expect(after.identityKeyId).not.toBe(before.identityKeyId);
    expect([...h.keystore.keys.keys()].sort()).toEqual([after.identityKeyId, after.sessionKeyId].sort());
  });
});

describe('signing jobs', () => {
  it('shows the job, signs after approval, and the server verifies the proof', async () => {
    const h = await setup();
    await h.pairNow();
    const { uuid, link } = h.server.createJob('Accomplishment Report – Sept', DOC_HASH);

    const outcome = await h.agent.handleLink(link);
    expect(outcome).toEqual({ result: 'completed', jobId: uuid });

    expect(h.confirms[0].job).toMatchObject({ document: { title: 'Accomplishment Report – Sept' }, signer: { name: 'Juan dela Cruz' } });
    expect(h.keystore.prompts.at(-1)).toBe('sign "Accomplishment Report – Sept" as Juan dela Cruz');
    const job = h.server.jobs.get(uuid)!;
    expect(job.status).toBe('completed');
    expect(job.result).toMatchObject({ device_uuid: h.store.list()[0].deviceUuid });
  });

  it('reports a decline to the server', async () => {
    const h = await setup();
    await h.pairNow();
    h.approve = false;
    const { uuid, link } = h.server.createJob('Leave form', DOC_HASH);
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'rejected', reason: 'declined' });
    expect(h.server.jobs.get(uuid)!.status).toBe('rejected');
  });

  it('treats a cancelled Touch ID / Hello prompt as a rejection', async () => {
    const h = await setup();
    await h.pairNow();
    h.keystore.cancelNextPrompt = true;
    const { uuid, link } = h.server.createJob('Leave form', DOC_HASH);
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'rejected', reason: 'os_prompt_cancelled' });
    expect(h.server.jobs.get(uuid)!.result).toEqual({ reason: 'os_prompt_cancelled' });
  });

  it('link tokens work once', async () => {
    const h = await setup();
    await h.pairNow();
    const { link } = h.server.createJob('Leave form', DOC_HASH);
    await h.agent.handleLink(link);
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'failed' });
    expect(h.confirms).toHaveLength(1);
  });

  it('refuses a job that belongs to a different user', async () => {
    const h = await setup({ server: { users: [{ id: '42', name: 'Juan' }, { id: '7', name: 'Maria' }] } });
    await h.pairNow();
    const { link } = h.server.createJob('Not yours', DOC_HASH, '7');
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'failed' });
    expect(h.confirms).toHaveLength(0);
  });

  it('drops links for unknown servers and malformed links without contacting anyone', async () => {
    const h = await setup();
    await h.pairNow();
    const { link } = h.server.createJob('Leave form', DOC_HASH);
    expect(await h.agent.handleLink(link.replace('s=test-server', 's=other-server'))).toEqual({
      result: 'ignored',
      reason: 'unknown server',
    });
    expect(await h.agent.handleLink('kukuxsign://job/nope')).toBeNull();
    expect(h.confirms).toHaveLength(0);
  });

  it('surfaces min_version refusals so the updater can run', async () => {
    const h = await setup();
    await h.pairNow();
    h.server.minVersion = '2.0.0';
    const { link } = h.server.createJob('Leave form', DOC_HASH);
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'failed', code: 'agent_outdated' });
  });
});

describe('request authentication', () => {
  it('a token without the session key is useless', async () => {
    const h = await setup();
    await h.pairNow();
    const token = h.store.token('test-server')!;
    const res = await fetch(`${h.server.origin}/signature/agent/status`, {
      headers: { Authorization: `Bearer ${token}`, 'X-Agent-Version': '1.0.0' },
    });
    expect(res.status).toBe(401);
  });

  it('the server rejects a replayed request proof', async () => {
    const h = await setup();
    await h.pairNow();
    const server = h.store.list()[0];
    const creds = h.agent.credentialsFor(server);
    const captured: RequestInit[] = [];
    const replaying = new AgentApi({
      origin: server.origin,
      agentVersion: '1.0.0',
      allowInsecureLocalhost: true,
      fetch: (url, init) => {
        captured.push(init);
        return fetch(url, init);
      },
    });
    await replaying.status(creds);
    const res = await fetch(`${server.origin}/signature/agent/status`, { ...captured[0], signal: undefined });
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe('replayed_request');
  });

  it('unpair revokes the token and deletes the local keys', async () => {
    const h = await setup();
    await h.pairNow();
    await h.agent.unpair('test-server');
    expect(h.store.list()).toEqual([]);
    expect(h.keystore.keys.size).toBe(0);
    expect([...h.server.devices.values()][0].revoked).toBe(true);
  });
});
