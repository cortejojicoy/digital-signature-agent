// Software certificates end to end (pkcs12-key-storage-plan.md §6, §8, §11.2):
// the real Agent against the mock server, with the memory key store standing
// in for the native PKCS#12 import.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Agent } from '../src/main/agent';
import { CertificateError, CertificateStore } from '../src/main/certificates';
import type { ConfirmRequest } from '../src/main/jobs';
import type { KeySource } from '../src/main/keystore';
import { PairingError, type PairingProgress } from '../src/main/pairing';
import { Store } from '../src/main/store';
import { fakeCipher } from './support/fake-cipher';
import { MemoryKeyStore, fixturePkcs12, type MemoryKeyStoreOptions } from './support/memory-keystore';
import { MockSigningServer, type MockServerOptions } from './support/mock-server';

const testRoot = readFileSync(path.join(__dirname, 'fixtures', 'pkcs12', 'test-root.cer'));
const first = fixturePkcs12('rsa2048-aes');
const second = fixturePkcs12('second');
const DOC_HASH = createHash('sha256').update('the exact PDF bytes').digest('hex');

interface Harness {
  server: MockSigningServer;
  keystore: MemoryKeyStore;
  store: Store;
  certificates: CertificateStore;
  agent: Agent;
  keyStorage: KeySource | null;
  confirms: ConfirmRequest[];
  progress: PairingProgress[];
  pair(server?: MockSigningServer, userId?: string): Promise<void>;
}

let dir: string;
const servers: MockSigningServer[] = [];

async function startServer(opts: MockServerOptions = {}): Promise<MockSigningServer> {
  const server = new MockSigningServer({ acceptsCertificates: true, trustedRoots: [testRoot], ...opts });
  await server.listen();
  servers.push(server);
  return server;
}

async function setup(
  opts: { server?: MockServerOptions; keystore?: MemoryKeyStoreOptions; keyStorage?: KeySource | null; name?: string } = {},
): Promise<Harness> {
  const server = await startServer(opts.server);
  return agentFor(server, opts);
}

async function agentFor(
  server: MockSigningServer,
  opts: { keystore?: MemoryKeyStoreOptions; keyStorage?: KeySource | null; name?: string } = {},
): Promise<Harness> {
  const keystore = new MemoryKeyStore({ pkcs12: [first, second], ...opts.keystore });
  const home = path.join(dir, opts.name ?? 'agent');
  const store = new Store(home, fakeCipher);
  await store.load();
  const certificates = new CertificateStore(home);
  await certificates.load();

  const h: Harness = {
    server,
    keystore,
    store,
    certificates,
    keyStorage: opts.keyStorage === undefined ? 'pkcs12' : opts.keyStorage,
    confirms: [],
    progress: [],
    agent: null as unknown as Agent,
    async pair(target = server, userId) {
      const { uuid, userCode } = target.startPairing(userId);
      await h.agent.pair(target.origin, userCode, {
        onProgress: (p) => {
          h.progress.push(p);
          if (p.stage === 'awaiting_confirmation') target.confirmPairing(uuid);
        },
      });
    },
  };
  h.agent = new Agent({
    keystore,
    store,
    certificates,
    keyStorage: () => h.keyStorage,
    agentVersion: '1.0.0',
    allowInsecureLocalNetwork: true,
    pollIntervalMs: 5,
    confirm: async (request) => {
      h.confirms.push(request);
      return true;
    },
  });
  return h;
}

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'agent-certs-'));
});
afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
  await rm(dir, { recursive: true, force: true });
});

const errorOf = (promise: Promise<unknown>) => promise.then(() => null).catch((e: unknown) => e);

describe('importing a certificate', () => {
  it('previews the certificate without importing anything', async () => {
    const h = await setup();
    const preview = await h.agent.inspectCertificate(first.data, 'test');
    expect(preview).toMatchObject({
      commonName: 'Test Signer rsa',
      organization: 'Kukux Test',
      issuerName: 'Kukux Test Signing CA',
      algorithm: 'RS256',
      keyBits: 2048,
      alreadyImported: false,
    });
    // Not under the Philippine PKI: a warning, not a refusal.
    expect(preview.warnings.map((w) => w.code)).toEqual(['not_pnpki']);
    expect(h.keystore.keys.size).toBe(0);
    expect(h.certificates.list()).toEqual([]);
  });

  it('imports the key under a certificate key id and keeps only public data', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    expect(cert.keyId).toBe(`ds.cert.${cert.id}.identity`);
    expect(h.keystore.keys.has(cert.keyId)).toBe(true);
    expect(h.certificates.active()).toMatchObject({ id: cert.id, commonName: 'Test Signer rsa', userPresence: true });
    expect(h.certificates.active()!.chain).toHaveLength(3);
    expect(JSON.stringify(h.certificates.list())).not.toContain('PRIVATE');
    expect((await h.agent.inspectCertificate(first.data, 'test')).alreadyImported).toBe(true);
  });

  it('importing the same certificate again keeps its key', async () => {
    const h = await setup();
    const a = await h.agent.importCertificate(first.data, 'test');
    const b = await h.agent.importCertificate(first.data, 'test');
    expect(b.id).toBe(a.id);
    expect(h.keystore.keys.size).toBe(1);
  });

  it('explains a wrong password, a file that is not PKCS#12, and an unsupported OS', async () => {
    const h = await setup();
    expect(await errorOf(h.agent.inspectCertificate(first.data, 'wrong'))).toMatchObject({
      code: 'E_BAD_PASSWORD',
      message: "That password doesn't open this file.",
    });
    expect(await errorOf(h.agent.importCertificate(Buffer.from('nope'), 'test'))).toMatchObject({ code: 'E_BAD_FILE' });

    const old = await setup({ keystore: { pkcs12Supported: false }, name: 'old-mac' });
    const err = await errorOf(old.agent.importCertificate(first.data, 'test'));
    expect(err).toBeInstanceOf(CertificateError);
    expect(err).toMatchObject({ code: 'E_UNSUPPORTED' });
  });
});

describe('pairing with a certificate', () => {
  it("uses the certificate's key as the identity key and sends the chain", async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();

    const [paired] = h.store.list();
    expect(paired).toMatchObject({ keySource: 'pkcs12', certificateId: cert.id, identityKeyId: cert.keyId, algorithm: 'RS256' });
    // Only a session key is new.
    expect([...h.keystore.keys.keys()].sort()).toEqual([cert.keyId, paired.sessionKeyId].sort());
    expect(h.keystore.prompts).toEqual(['pair this computer with Test Signing App']);

    const device = [...h.server.devices.values()][0];
    expect(device).toMatchObject({ keySource: 'pkcs12', certificateFingerprint: cert.fingerprint256, protection: 'software' });
    expect(device.certificateSubject).toContain('CN=Test Signer rsa');

    expect(h.agent.servers()[0]).toMatchObject({ keySource: 'pkcs12', certificateName: 'Test Signer rsa' });
    expect(h.agent.certificateSummaries()).toMatchObject([{ id: cert.id, active: true, usedBy: ['Test Signing App'] }]);
  });

  it('signs jobs with the certificate key, and the server verifies them', async () => {
    const h = await setup();
    await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    const job = h.server.createJob('Leave form', DOC_HASH);

    expect(await h.agent.handleLink(job.link)).toEqual({ result: 'completed', jobId: job.uuid });
    expect(h.server.jobs.get(job.uuid)!.status).toBe('completed');
    expect(h.keystore.prompts.at(-1)).toBe('sign "Leave form" with your certificate (Test Signer rsa)');
  });

  it('one certificate key serves several apps', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    const other = await startServer({ serverId: 'other-app', serverName: 'Other App' });
    await h.pair();
    await h.pair(other);

    expect(h.store.list().map((s) => s.identityKeyId)).toEqual([cert.keyId, cert.keyId]);
    expect(h.keystore.keys.size).toBe(3); // the certificate key and two session keys
  });

  it("stops before any key or prompt when the app doesn't accept certificates", async () => {
    const h = await setup({ server: { acceptsCertificates: false } });
    const cert = await h.agent.importCertificate(first.data, 'test');
    const err = await errorOf(h.pair());
    expect(err).toBeInstanceOf(PairingError);
    expect(err).toMatchObject({ code: 'certificates_disabled' });
    expect([...h.keystore.keys.keys()]).toEqual([cert.keyId]);
    expect(h.keystore.prompts).toEqual([]);
  });

  it('needs a key storage choice, and a certificate when it is the choice', async () => {
    const unchosen = await setup({ keyStorage: null });
    expect(await errorOf(unchosen.pair())).toMatchObject({ code: 'no_key_storage' });

    const noCert = await setup({ name: 'no-cert' });
    expect(await errorOf(noCert.pair())).toMatchObject({ code: 'certificate_missing' });
  });

  it('surfaces the server refusing an untrusted or revoked certificate, and cleans up the session key', async () => {
    const untrusted = await setup({ server: { trustedRoots: [] } });
    const cert = await untrusted.agent.importCertificate(first.data, 'test');
    expect(await errorOf(untrusted.pair())).toMatchObject({
      code: 'certificate_untrusted',
      message: "Test Signing App doesn't accept certificates from Kukux Test Signing CA.",
    });
    expect([...untrusted.keystore.keys.keys()]).toEqual([cert.keyId]);

    const serial = cert.serialHex;
    const revoked = await setup({ server: { revokedSerials: [serial] }, name: 'revoked' });
    await revoked.agent.importCertificate(first.data, 'test');
    expect(await errorOf(revoked.pair())).toMatchObject({ code: 'certificate_revoked' });
  });

  it('refuses the same certificate on a second computer', async () => {
    const two = { users: [{ id: '42', name: 'Juan dela Cruz' }, { id: '7', name: 'Maria Santos' }] };
    const h = await setup({ server: two });
    await h.agent.importCertificate(first.data, 'test');
    await h.pair();

    const laptop = await agentFor(h.server, { name: 'laptop', keystore: { device: { hardwareUuid: 'OTHER-UUID' } } });
    await laptop.agent.importCertificate(first.data, 'test');
    const err = await errorOf(laptop.pair(h.server, '7'));
    expect(err).toMatchObject({ code: 'certificate_in_use', manageUrl: `${h.server.origin}/devices` });
    expect((err as Error).message).toContain('already paired on Juan’s MacBook Pro');
  });
});

describe("a certificate's key is deleted only with the certificate (§6.5)", () => {
  it('unpairing keeps it', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    await h.agent.unpair('test-server');
    expect([...h.keystore.keys.keys()]).toEqual([cert.keyId]);
  });

  it('removing locally while offline keeps it', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    const { sessionKeyId } = h.store.list()[0];
    h.server.failNextUnpair = true;
    expect(await h.agent.unpair('test-server', { offline: 'remove' })).toEqual({ status: 'removed_locally' });
    expect([...h.keystore.keys.keys()].sort()).toEqual([cert.keyId, sessionKeyId].sort());
  });

  it('re-pairing keeps it, and a failed pairing does not take it along', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    await h.pair(); // re-pair: the old session key goes, the certificate key stays
    expect([...h.keystore.keys.keys()].sort()).toEqual([cert.keyId, h.store.list()[0].sessionKeyId].sort());

    const declined = h.server.startPairing();
    await errorOf(
      h.agent.pair(h.server.origin, declined.userCode, {
        onProgress: (p) => p.stage === 'awaiting_confirmation' && h.server.confirmPairing(declined.uuid, false),
      }),
    );
    expect(h.keystore.keys.has(cert.keyId)).toBe(true);
  });

  it('removing the certificate is refused while an app uses it', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    expect(await errorOf(h.agent.removeCertificate(cert.id))).toMatchObject({
      code: 'in_use',
      message: 'Unpair Test Signing App first: it signs with this certificate.',
    });

    await h.agent.unpair('test-server');
    await h.agent.removeCertificate(cert.id);
    expect(h.keystore.keys.size).toBe(0);
    expect(h.certificates.list()).toEqual([]);
  });
});

describe('switching storage and replacing a certificate', () => {
  it('re-pairs an app from the security chip to the certificate, asking first', async () => {
    const h = await setup({ keyStorage: 'platform' });
    await h.pair();
    const before = h.store.list()[0];
    expect(before.keySource).toBe('platform');

    h.keyStorage = 'pkcs12';
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    expect(h.progress).toContainEqual(
      expect.objectContaining({ stage: 'already_paired_locally', from: 'platform', to: 'pkcs12' }),
    );
    const after = h.store.list()[0];
    expect(after).toMatchObject({ keySource: 'pkcs12', identityKeyId: cert.keyId });
    // The old platform identity key is gone with the old pairing.
    expect(h.keystore.keys.has(before.identityKeyId)).toBe(false);
    // The server rebound the same device instead of adding one.
    expect([...h.server.devices.values()].filter((d) => !d.revoked)).toHaveLength(1);
  });

  it('keeps the old certificate while an app still uses it, and drops it after re-pairing', async () => {
    const h = await setup();
    const old = await h.agent.importCertificate(first.data, 'test');
    await h.pair();

    const renewed = await h.agent.importCertificate(second.data, 'test');
    expect(h.certificates.active()!.id).toBe(renewed.id);
    expect(h.agent.certificateSummaries()).toMatchObject([
      { id: old.id, active: false, usedBy: ['Test Signing App'] },
      { id: renewed.id, active: true, usedBy: [] },
    ]);

    await h.pair(); // re-pair with the new certificate
    expect(h.store.list()[0].certificateId).toBe(renewed.id);
    expect(h.certificates.list().map((c) => c.id)).toEqual([renewed.id]);
    expect(h.keystore.keys.has(old.keyId)).toBe(false);
  });

  it('an unused older certificate goes as soon as a new one is imported', async () => {
    const h = await setup();
    const old = await h.agent.importCertificate(first.data, 'test');
    await h.agent.importCertificate(second.data, 'test');
    expect(h.certificates.list()).toHaveLength(1);
    expect(h.keystore.keys.has(old.keyId)).toBe(false);
  });
});
