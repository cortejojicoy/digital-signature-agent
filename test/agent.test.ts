// End to end: the real Agent (pairing, jobs, API client, store) against the
// mock server over HTTP, with a software key store.
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { networkInterfaces, tmpdir } from 'node:os';
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
    allowInsecureLocalNetwork: true,
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
    await expect(h.agent.pair('http://evil.example.com', 'AAAA-BBBB')).rejects.toThrow(/HTTPS/);
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

const HAS_LAN = Object.values(networkInterfaces()).some((list) =>
  list?.some((a) => a.family === 'IPv4' && !a.internal && /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(a.address)),
);

describe('local network (npm run dev)', () => {
  it.skipIf(!HAS_LAN)('pairs and signs against a server on a LAN address', async () => {
    const h = await setup({ server: { lan: true } });
    expect(h.server.origin).toMatch(/^http:\/\/(?:10|172|192)\./);
    await h.pairNow();
    expect(h.store.list()[0].origin).toBe(h.server.origin);

    const { link } = h.server.createJob('LAN test', DOC_HASH);
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'completed' });
  });

  it('stops using HTTP pairings when Developer mode is turned off', async () => {
    const h = await setup();
    await h.pairNow();
    expect(h.agent.servers()[0].insecure).toBe(true);

    h.agent.setAllowInsecureLocalNetwork(false);
    const { link } = h.server.createJob('After dev mode', DOC_HASH);
    // Job links carry no origin, so they still arrive; the job fails cleanly.
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'failed', error: expect.stringMatching(/Developer mode/) });
    expect(h.confirms).toHaveLength(0);
    await expect(h.agent.pair(h.server.origin, 'AAAA-BBBB')).rejects.toThrow(/HTTPS address/);
  });

    it('refuses to pair when the server reports a different origin', async () => {
    const h = await setup();
    const { userCode } = h.server.startPairing();
    const other = h.server.origin.replace('127.0.0.1', 'localhost');
    await expect(h.agent.pair(other, userCode)).rejects.toThrow(/APP_URL/);
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
      allowInsecureLocalNetwork: true,
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

// ── One signature per app, per computer (multi-app-pairing-plan.md) ──

/** Another agent install (its own store and keys) next to the harness's server. */
async function agentFor(keystore: MemoryKeyStore, name: string): Promise<{ agent: Agent; store: Store }> {
  const store = new Store(path.join(dir, name), fakeCipher);
  await store.load();
  const agent = new Agent({
    keystore,
    store,
    agentVersion: '1.0.0',
    allowInsecureLocalNetwork: true,
    pollIntervalMs: 5,
    confirm: async () => true,
  });
  return { agent, store };
}

async function pairAs(agent: Agent, server: MockSigningServer, userId: string, opts: { confirmRepair?: () => Promise<boolean> } = {}) {
  const { uuid, userCode } = server.startPairing(userId);
  return agent.pair(server.origin, userCode, {
    confirmRepair: opts.confirmRepair,
    onProgress: (p) => {
      if (p.stage === 'awaiting_confirmation') server.confirmPairing(uuid);
    },
  });
}

const TWO_USERS = { users: [{ id: '42', name: 'Juan dela Cruz' }, { id: '7', name: 'Maria Santos' }] };

describe('one signature per app', () => {
  it('holds one signature for each of several apps', async () => {
    const h = await setup({ server: { serverId: 'amp', serverName: 'AMP' } });
    const sims = new MockSigningServer({ serverId: 'sims', serverName: 'SIMS', users: [{ id: '7', name: 'Maria Santos' }] });
    await sims.listen();
    try {
      await h.pairNow();
      await pairAs(h.agent, sims, '7');
      expect(h.store.list().map((s) => [s.id, s.userName])).toEqual([
        ['amp', 'Juan dela Cruz'],
        ['sims', 'Maria Santos'],
      ]);
      expect(h.keystore.keys.size).toBe(4);
    } finally {
      await sims.close();
    }
  });

  it('refuses a second account for the same app before creating any key', async () => {
    const h = await setup({ server: TWO_USERS });
    await h.pairNow();
    const keysBefore = [...h.keystore.keys.keys()];
    const promptsBefore = h.keystore.prompts.length;

    const err = await pairAs(h.agent, h.server, '7').catch((e) => e);
    expect(err).toBeInstanceOf(PairingError);
    expect(err.code).toBe('app_already_paired');
    expect(err.serverId).toBe('test-server');
    expect(err.message).toMatch(/already holds Juan dela Cruz's signature for Test Signing App/);
    // Nothing created, no OS prompt, Juan's pairing untouched.
    expect([...h.keystore.keys.keys()]).toEqual(keysBefore);
    expect(h.keystore.prompts).toHaveLength(promptsBefore);
    expect(h.store.list()[0].userId).toBe('42');
    expect([...h.server.devices.values()]).toHaveLength(1);
  });

  it('pairs the other account once the first is unpaired', async () => {
    const h = await setup({ server: TWO_USERS });
    await h.pairNow();
    await h.agent.unpair('test-server');
    await pairAs(h.agent, h.server, '7');
    expect(h.store.list()[0]).toMatchObject({ userId: '7', userName: 'Maria Santos' });
  });

  it('asks before re-pairing the same account, and stops cleanly on "keep"', async () => {
    const h = await setup();
    await h.pairNow();
    const before = h.store.list()[0];
    const keysBefore = [...h.keystore.keys.keys()];
    const stages: string[] = [];

    const { uuid, userCode } = h.server.startPairing();
    const err = await h.agent
      .pair(h.server.origin, userCode, {
        onProgress: (p) => stages.push(p.stage),
        confirmRepair: async () => false,
      })
      .catch((e) => e);
    expect(err.code).toBe('aborted');
    expect(stages).toEqual(['looking_up', 'already_paired_locally']);
    expect([...h.keystore.keys.keys()]).toEqual(keysBefore);
    expect(h.store.list()[0]).toEqual(before);
    expect(h.server.pairings.get(uuid)!.status).toBe('pending');
  });

  it('re-pairing the same account updates the existing device instead of adding one', async () => {
    const h = await setup();
    await h.pairNow();
    const before = h.store.list()[0];

    let existing: string | undefined;
    let rebound: boolean | undefined;
    const { uuid, userCode } = h.server.startPairing();
    await h.agent.pair(h.server.origin, userCode, {
      confirmRepair: async () => true,
      onProgress: (p) => {
        if (p.stage === 'awaiting_confirmation') {
          existing = p.existingDevice?.label;
          h.server.confirmPairing(uuid);
        }
        if (p.stage === 'paired') rebound = p.rebound;
      },
    });

    const after = h.store.list()[0];
    expect(existing).toBe('Juan’s MacBook Pro');
    expect(rebound).toBe(true);
    expect(after.deviceUuid).toBe(before.deviceUuid);
    expect(after.identityKeyId).not.toBe(before.identityKeyId);
    expect([...h.server.devices.values()]).toHaveLength(1);
    // Only the new keys remain, and they work.
    expect([...h.keystore.keys.keys()].sort()).toEqual([after.identityKeyId, after.sessionKeyId].sort());
    const { link } = h.server.createJob('After re-pair', DOC_HASH);
    expect(await h.agent.handleLink(link)).toMatchObject({ result: 'completed' });
  });

  it('surfaces the server refusing a computer another account holds', async () => {
    // Juan's install on this computer, then a fresh install (same hardware) pairing Maria.
    const h = await setup({ server: TWO_USERS });
    await h.pairNow();
    const other = new MemoryKeyStore();
    const fresh = await agentFor(other, 'reinstall');

    const err = await pairAs(fresh.agent, h.server, '7').catch((e) => e);
    expect(err).toBeInstanceOf(PairingError);
    expect(err.code).toBe('machine_already_paired');
    expect(err.message).toMatch(/already paired with another account/);
    expect(err.message).not.toMatch(/Juan/);
    expect(other.keys.size).toBe(0);
    expect(fresh.store.list()).toEqual([]);
  });

  it('lets the other account pair once an admin releases the computer', async () => {
    const h = await setup({ server: TWO_USERS });
    await h.pairNow();
    h.server.releaseDevice(h.store.list()[0].deviceUuid);
    const fresh = await agentFor(new MemoryKeyStore(), 'released');
    await pairAs(fresh.agent, h.server, '7');
    expect(fresh.store.list()[0].userId).toBe('7');
  });

  it('sends a null hardware id when the firmware has no usable uuid', async () => {
    const h = await setup({ keystore: { device: { hardwareUuid: '' } } });
    await h.pairNow();
    expect([...h.server.devices.values()][0].hardwareIdHash).toBeNull();
  });
});

describe('device types', () => {
  it('reports the detected type and stores what the server confirmed', async () => {
    const h = await setup({ keystore: { device: { model: 'Mac mini (2024)', modelIdentifier: 'Mac16,10', formFactor: 'desktop' } } });
    await h.pairNow();
    expect([...h.server.devices.values()][0].deviceType).toBe('mac_mini');
    expect(h.store.list()[0].deviceType).toBe('mac_mini');
    expect(h.agent.servers()[0].deviceType).toBe('mac_mini');
  });

  it('refuses a virtual machine before creating any key', async () => {
    const h = await setup({ keystore: { device: { virtual: true } } });
    const { userCode } = h.server.startPairing();
    const err = await h.agent.pair(h.server.origin, userCode).catch((e) => e);
    expect(err).toBeInstanceOf(PairingError);
    expect(err.code).toBe('device_type_not_allowed');
    expect(err.message).toMatch(/virtual machine/);
    expect(h.keystore.keys.size).toBe(0);
    expect(h.keystore.prompts).toEqual([]);
  });

  it('pairs a virtual machine where the server allows it', async () => {
    const h = await setup({ server: { blockedDeviceTypes: [] }, keystore: { device: { virtual: true } } });
    await h.pairNow();
    expect([...h.server.devices.values()][0]).toMatchObject({ deviceType: 'virtual_machine', virtual: true });
  });

  it('still refuses when only the server knows the type is blocked', async () => {
    // An older lookup without blocked_device_types: the claim is the authority.
    const h = await setup({ keystore: { device: { virtual: true } } });
    const patched = h.server as unknown as { lookup: (json: object) => Record<string, unknown> };
    const lookup = patched.lookup.bind(h.server);
    patched.lookup = (json) => ({ ...lookup(json), blocked_device_types: undefined });
    const { userCode } = h.server.startPairing();
    const err = await h.agent.pair(h.server.origin, userCode).catch((e) => e);
    expect(err.code).toBe('device_type_not_allowed');
    expect(h.keystore.keys.size).toBe(0);
  });

  it('fills in the type of a pairing made before device types existed', async () => {
    const h = await setup();
    await h.pairNow();
    const { deviceType: _dropped, ...legacy } = h.store.list()[0];
    await h.store.update(legacy);
    expect(h.store.list()[0].deviceType).toBeUndefined();

    await h.agent.init();
    expect(h.store.list()[0].deviceType).toBe('macbook_pro');
  });
});

describe('other devices', () => {
  it("lists the account's other computers for each app", async () => {
    const h = await setup();
    await h.pairNow();
    const office = await agentFor(new MemoryKeyStore({ device: { hardwareUuid: 'OFFICE-MINI', hostname: 'Office Mac mini', model: 'Mac mini (2024)' } }), 'office');
    await pairAs(office.agent, h.server, '42');

    expect(await h.agent.refreshOtherDevices(true)).toBe(true);
    expect(h.agent.servers()[0].otherDevices).toEqual([{ label: 'Office Mac mini', deviceType: 'mac_mini' }]);
    // Throttled: a second call within a minute doesn't ask again.
    expect(await h.agent.refreshOtherDevices()).toBe(false);
  });
});

describe('unpair while the server is unreachable', () => {
  it('removes the pairing and the signing key at once, and queues the revoke', async () => {
    const h = await setup();
    await h.pairNow();
    const server = h.store.list()[0];
    h.server.failNextUnpair = true;

    await h.agent.unpair('test-server');
    expect(h.store.list()).toEqual([]);
    expect(h.store.pendingRevokes()).toMatchObject([{ serverId: 'test-server', deviceUuid: server.deviceUuid }]);
    // The signing key is gone; only the session key stays, to authenticate the retry.
    expect([...h.keystore.keys.keys()]).toEqual([server.sessionKeyId]);
    expect(h.server.devices.get(server.deviceUuid)!.revoked).toBe(false);

    await h.agent.retryRevokes();
    expect(h.server.devices.get(server.deviceUuid)!.revoked).toBe(true);
    expect(h.store.pendingRevokes()).toEqual([]);
    expect(h.keystore.keys.size).toBe(0);
  });

  it('keeps a revoke queued while the server is still unreachable', async () => {
    const h = await setup();
    await h.pairNow();
    h.server.failNextUnpair = true;
    await h.agent.unpair('test-server');
    h.server.failNextUnpair = true;
    await h.agent.retryRevokes();
    expect(h.store.pendingRevokes()).toHaveLength(1);
  });

  it('drops a queued revoke the web already did', async () => {
    const h = await setup();
    await h.pairNow();
    const { deviceUuid } = h.store.list()[0];
    h.server.failNextUnpair = true;
    await h.agent.unpair('test-server');
    h.server.releaseDevice(deviceUuid); // revoked on the web meanwhile: the token now gets a 401

    await h.agent.retryRevokes();
    expect(h.store.pendingRevokes()).toEqual([]);
    expect(h.keystore.keys.size).toBe(0);
  });

  it('finishes the revoke before pairing a different account', async () => {
    const h = await setup({ server: TWO_USERS });
    await h.pairNow();
    h.server.failNextUnpair = true;
    await h.agent.unpair('test-server');

    // Without the retry, the server would still count this computer as Juan's.
    await pairAs(h.agent, h.server, '7');
    expect(h.store.list()[0].userId).toBe('7');
    expect(h.store.pendingRevokes()).toEqual([]);
  });
});
