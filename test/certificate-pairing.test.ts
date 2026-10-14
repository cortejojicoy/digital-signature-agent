// Software certificates end to end (pkcs12-key-storage-plan.md §6, §8, §11.2;
// certificate-password-pairing-plan.md §3–§5, §11): the real Agent against the
// mock server, with the memory key store standing in for the native import.
// Certificate keys are unlocked by the certificate password ("test" for the
// fixtures), never by an OS prompt.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Agent } from '../src/main/agent';
import { CertificateError, CertificateStore } from '../src/main/certificates';
import type { Approval, ConfirmRequest, RetryReason } from '../src/main/jobs';
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
  /** What the confirm window answers, in order; then the right password. */
  answers: Approval[];
  /** Why the confirm window was asked again. */
  retries: RetryReason[];
  progress: PairingProgress[];
  pair(server?: MockSigningServer, userId?: string, password?: string): Promise<void>;
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
    answers: [],
    retries: [],
    progress: [],
    agent: null as unknown as Agent,
    async pair(target = server, userId, password = 'test') {
      const { uuid, userCode } = target.startPairing(userId);
      await h.agent.pair(target.origin, userCode, {
        password,
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
    confirm: async (request, retry) => {
      h.confirms.push(request);
      if (retry) h.retries.push(retry);
      return h.answers.shift() ?? { approved: true, password: 'test' };
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
    // The certificate password signed the registration proof: no OS prompt.
    expect(h.keystore.prompts).toEqual([]);
    expect(h.keystore.passwords).toEqual(['test']);

    const device = [...h.server.devices.values()][0];
    expect(device).toMatchObject({
      keySource: 'pkcs12',
      certificateFingerprint: cert.fingerprint256,
      protection: 'software',
      userPresence: true,
      presenceMethod: 'certificate_password',
    });
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
    expect(h.keystore.prompts).toEqual([]);
    expect(h.keystore.passwords.at(-1)).toBe('test');
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

describe('pairing from the link (certificate-password-pairing-plan.md §3)', () => {
  it('previews the app, account and certificate without changing anything', async () => {
    const h = await setup();
    await h.agent.importCertificate(first.data, 'test');
    const { uuid, userCode } = h.server.startPairing();

    const preview = await h.agent.previewPairing(h.server.origin, userCode);
    expect(preview).toEqual({
      serverName: 'Test Signing App',
      origin: h.server.origin,
      userName: 'Juan dela Cruz',
      repair: false,
      certificateName: 'Test Signer rsa',
    });
    expect(h.server.pairings.get(uuid)!.status).toBe('pending');
    expect(h.keystore.keys.size).toBe(1); // only the certificate key

    // The same code still pairs afterwards.
    await h.pair();
    expect(h.store.list()).toHaveLength(1);
    expect((await h.agent.previewPairing(h.server.origin, h.server.startPairing().userCode)).repair).toBe(true);
  });

  it('refuses in the preview what pairing would refuse, before any password', async () => {
    const h = await setup({ server: { acceptsCertificates: false } });
    await h.agent.importCertificate(first.data, 'test');
    expect(await errorOf(h.agent.previewPairing(h.server.origin, h.server.startPairing().userCode))).toMatchObject({
      code: 'certificates_disabled',
    });
    const none = await setup({ name: 'none' });
    expect(await errorOf(none.agent.previewPairing(none.server.origin, none.server.startPairing().userCode))).toMatchObject({
      code: 'certificate_missing',
    });
  });

  it('a wrong password stops before the claim, and sends nothing', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    const err = await errorOf(h.pair(h.server, undefined, 'wrong'));
    expect(err).toBeInstanceOf(PairingError);
    expect(err).toMatchObject({ code: 'bad_password', message: 'Wrong certificate password.' });
    // Not claimed: the server never saw the keys.
    expect([...h.server.pairings.values()].map((p) => p.status)).toEqual(['pending']);
    // The session key made for it is gone; the certificate key stays.
    expect([...h.keystore.keys.keys()]).toEqual([cert.keyId]);
  });
});

describe('the certificate password (certificate-password-pairing-plan.md §4)', () => {
  it('asks again after a wrong password, leaving the job open, then signs', async () => {
    const h = await setup();
    await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    const job = h.server.createJob('Leave form', DOC_HASH);
    h.answers.push({ approved: true, password: 'nope' }, { approved: true }, { approved: true, password: 'test' });

    expect(await h.agent.handleLink(job.link)).toEqual({ result: 'completed', jobId: job.uuid });
    expect(h.retries).toEqual([
      { code: 'E_BAD_PASSWORD', error: 'Wrong certificate password.', retryAt: undefined },
      { code: 'E_BAD_PASSWORD', error: 'Enter your certificate password.', retryAt: undefined },
    ]);
    expect(h.confirms).toHaveLength(3);
    expect(h.server.jobs.get(job.uuid)!.status).toBe('completed');
  });

  it('declining with the password window open rejects the job', async () => {
    const h = await setup();
    await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    const job = h.server.createJob('Leave form', DOC_HASH);
    h.answers.push({ approved: true, password: 'nope' }, { approved: false });
    expect(await h.agent.handleLink(job.link)).toEqual({ result: 'rejected', jobId: job.uuid, reason: 'declined' });
    expect(h.server.jobs.get(job.uuid)!.status).toBe('rejected');
  });

  it('waits 30 s after 5 wrong passwords, doubling, and resets on the right one', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    const server = h.store.list()[0];
    const sign = (password: string) => h.agent.signIdentity(server, Buffer.from('m'), 'test', undefined, password);

    for (let i = 0; i < 4; i++) expect(await errorOf(sign('nope'))).toMatchObject({ code: 'E_BAD_PASSWORD', retryAt: undefined });
    const fifth = (await errorOf(sign('nope'))) as { retryAt: string; message: string };
    expect(fifth.message).toMatch(/Try again in 30 seconds/);
    const wait = Date.parse(fifth.retryAt) - Date.now();
    expect(wait).toBeGreaterThan(25_000);
    expect(wait).toBeLessThanOrEqual(30_000);

    // Locked: even the right password waits, and the key isn't tried.
    const tries = h.keystore.passwords.length;
    expect(await errorOf(sign('test'))).toMatchObject({ code: 'E_LOCKED' });
    expect(h.keystore.passwords).toHaveLength(tries);

    // After the wait the right password works and clears the count.
    await h.certificates.recordPassword(cert.id, false); // a sixth miss doubles the wait…
    expect(Date.parse(h.certificates.get(cert.id)!.lockedUntil!) - Date.now()).toBeGreaterThan(55_000);
    await h.certificates.recordPassword(cert.id, true); // …and a right one (after the wait) clears it
    await expect(sign('test')).resolves.toBeInstanceOf(Buffer);
    expect(h.certificates.get(cert.id)).not.toHaveProperty('failedAttempts');
  });
});

describe('one key storage at a time (certificate-password-pairing-plan.md §5)', () => {
  it('switching to the certificate unpairs the security-chip apps on the server and deletes their keys', async () => {
    const h = await setup({ keyStorage: 'platform' });
    const other = await startServer({ serverId: 'other-app', serverName: 'Other App' });
    await h.pair();
    await h.pair(other);
    const before = h.store.list();
    expect(h.agent.pairingsOutside('pkcs12').map((s) => s.name)).toEqual(['Test Signing App', 'Other App']);

    other.failNextUnpair = true; // one of them can't be reached
    const result = await h.agent.switchKeyStorage('pkcs12');
    expect(result).toEqual({ unpaired: ['Test Signing App'], queued: ['Other App'], failed: [] });
    expect(h.store.list()).toEqual([]);
    for (const s of before) expect(h.keystore.keys.has(s.identityKeyId)).toBe(false);
    expect([...h.server.devices.values()][0].revoked).toBe(true);
    // The unreachable one waits as a queued revoke, holding only its session key.
    expect(h.store.pendingRevokes().map((r) => r.serverName)).toEqual(['Other App']);
  });

  it('switching to the security chip keeps the certificate unless asked to remove it', async () => {
    const h = await setup();
    const cert = await h.agent.importCertificate(first.data, 'test');
    await h.pair();

    await h.agent.switchKeyStorage('platform');
    expect(h.store.list()).toEqual([]);
    expect(h.certificates.active()?.id).toBe(cert.id);
    expect(h.keystore.keys.has(cert.keyId)).toBe(true);

    await h.agent.switchKeyStorage('platform', { removeCertificate: true });
    expect(h.certificates.list()).toEqual([]);
    expect(h.keystore.keys.size).toBe(0);
  });

  it('with nothing paired in the other storage, switching changes no pairing', async () => {
    const h = await setup();
    await h.agent.importCertificate(first.data, 'test');
    await h.pair();
    expect(await h.agent.switchKeyStorage('pkcs12')).toEqual({ unpaired: [], queued: [], failed: [] });
    expect(h.store.list()).toHaveLength(1);
  });
});

