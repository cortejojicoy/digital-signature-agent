// The import preview's checks and the certificate store (pkcs12-key-storage-plan.md §6.2).
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CertificateError, CertificateStore, describeChain, keyUsage, newCertificateIds } from '../src/main/certificates';
import { PNPKI_ROOTS } from '../src/main/pnpki';

const fixture = (name: string) => readFileSync(path.join(__dirname, 'fixtures', 'pkcs12', name));
const leaf = fixture('rsa2048-leaf.cer');
const intermediate = fixture('test-intermediate.cer');
const root = fixture('test-root.cer');
const testRoots = [{ fingerprint256: new X509Certificate(root).fingerprint256, pem: new X509Certificate(root).toString() }];
const now = Date.parse('2027-01-01T00:00:00Z');

describe('describeChain', () => {
  it('orders the chain from the leaf up, whatever order the file had', () => {
    const d = describeChain([leaf, root, intermediate], now, testRoots);
    expect(d.chain).toEqual([leaf, intermediate, root]);
    expect(d.commonName).toBe('Test Signer rsa');
    expect(d.organization).toBe('Kukux Test');
    expect(d.issuerName).toBe('Kukux Test Signing CA');
    expect(d.serialHex).toBe(new X509Certificate(leaf).serialNumber.toUpperCase());
    expect(d.pnpki).toBe(true);
    expect(d.warnings).toEqual([]);
  });

  it('drops certificates that are not part of the chain', () => {
    const d = describeChain([leaf, fixture('second-leaf.cer'), intermediate, root], now, testRoots);
    expect(d.chain).toEqual([leaf, intermediate, root]);
  });

  it('warns when the chain stops short or is not under a known root', () => {
    const d = describeChain([leaf, intermediate], now, PNPKI_ROOTS);
    expect(d.pnpki).toBe(false);
    expect(d.warnings.map((w) => w.code)).toEqual(['incomplete_chain', 'not_pnpki']);

    const outside = describeChain([leaf, intermediate, root], now, PNPKI_ROOTS);
    expect(outside.warnings.map((w) => w.code)).toEqual(['not_pnpki']);
  });

  it('recognises a chain that ends just below a known root', () => {
    expect(describeChain([leaf, intermediate], now, testRoots).pnpki).toBe(true);
  });

  it('warns 30 days before expiry, and refuses an expired certificate', () => {
    const notAfter = Date.parse(new X509Certificate(leaf).validTo);
    const soon = describeChain([leaf, intermediate, root], notAfter - 5 * 86_400_000, testRoots);
    expect(soon.warnings).toEqual([{ code: 'expires_soon', message: expect.stringContaining('5 days') }]);

    expect(() => describeChain([fixture('expired-leaf.cer'), intermediate, root], now, testRoots)).toThrow(
      expect.objectContaining({ code: 'expired' }),
    );
  });

  it('refuses a certificate that may not sign, and a CA certificate', () => {
    const encipher = () => describeChain([fixture('no-nonrepudiation-leaf.cer'), intermediate], now, testRoots);
    expect(encipher).toThrow(CertificateError);
    expect(encipher).toThrow(expect.objectContaining({ code: 'not_a_signing_certificate' }));
    expect(() => describeChain([intermediate, root], now, testRoots)).toThrow(
      expect.objectContaining({ code: 'not_a_signing_certificate' }),
    );
  });

  it('refuses something that is not a certificate', () => {
    expect(() => describeChain([Buffer.from('nope')], now)).toThrow(expect.objectContaining({ code: 'invalid_certificate' }));
    expect(() => describeChain([], now)).toThrow(expect.objectContaining({ code: 'invalid_certificate' }));
  });
});

describe('keyUsage', () => {
  it('reads the key usage bits', () => {
    expect(keyUsage(leaf)).toEqual({ digitalSignature: true, nonRepudiation: true });
    expect(keyUsage(fixture('no-nonrepudiation-leaf.cer'))).toEqual({ digitalSignature: false, nonRepudiation: false });
    expect(keyUsage(intermediate)).toEqual({ digitalSignature: false, nonRepudiation: false });
  });

  it('pins a well-formed PNPKI root', () => {
    const [pnpki] = PNPKI_ROOTS;
    const cert = new X509Certificate(pnpki.pem);
    expect(cert.fingerprint256).toBe(pnpki.fingerprint256);
    expect(cert.subject).toContain('CN=Philippine Root CA - G2');
    expect(cert.verify(cert.publicKey)).toBe(true);
  });
});

describe('CertificateStore', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'certs-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('keeps the newest certificate active and survives a reload', async () => {
    const store = new CertificateStore(dir);
    await store.load();
    expect(store.active()).toBeNull();

    const first = { ...sample(), ...newCertificateIds(), fingerprint256: 'AA' };
    const second = { ...sample(), ...newCertificateIds(), fingerprint256: 'BB' };
    await store.save(first);
    await store.save(second);
    expect(store.active()?.id).toBe(second.id);
    expect(second.keyId).toMatch(/^ds\.cert\.[0-9a-f]{16}\.identity$/);

    const reloaded = new CertificateStore(dir);
    await reloaded.load();
    expect(reloaded.list().map((c) => c.id)).toEqual([first.id, second.id]);
    expect(reloaded.findByFingerprint('AA')?.id).toBe(first.id);

    await reloaded.remove(second.id);
    expect(reloaded.active()?.id).toBe(first.id);
  });
});

function sample() {
  return {
    subject: 'CN=Test Signer rsa',
    commonName: 'Test Signer rsa',
    organization: 'Kukux Test',
    issuer: 'CN=Kukux Test Signing CA',
    issuerName: 'Kukux Test Signing CA',
    serialHex: '01',
    notBefore: '2026-01-01T00:00:00.000Z',
    notAfter: '2036-01-01T00:00:00.000Z',
    chain: [leaf.toString('base64')],
    algorithm: 'RS256' as const,
    protection: 'software' as const,
    userPresence: true,
    pnpki: false,
    importedAt: '2026-10-13T00:00:00.000Z',
  };
}
