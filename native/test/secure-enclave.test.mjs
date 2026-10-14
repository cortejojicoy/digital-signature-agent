// Secure Enclave keys outside the keychain (SecureEnclaveBlob.swift), the
// path free / ad-hoc signed builds use. Skipped where there is no Secure
// Enclave (CI VMs, Intel Macs without T2, Windows). No key here requires
// presence, so no Touch ID / password prompt appears.
import assert from 'node:assert/strict';
import { X509Certificate, createPublicKey, randomBytes, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

process.env.KUKUX_KEYSTORE_BACKEND = 'auto';

const require = createRequire(import.meta.url);
const ks = require('../build/Release/keystore.node');

const dir = mkdtempSync(path.join(tmpdir(), 'kse-'));
const keyId = `ds.test.${randomBytes(6).toString('hex')}`;
let hardware = false;

before(async () => {
  ks.configure({ keyDirectory: dir });
  hardware = process.platform === 'darwin' && (await ks.capabilities()).hardware;
});

after(async () => {
  if (hardware) await ks.deleteKey(keyId);
  rmSync(dir, { recursive: true, force: true });
});

test('creates a Secure Enclave key without keychain entitlements', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  const info = await ks.createKey({ keyId, requireUserPresence: false });
  assert.equal(info.protection, 'secure_enclave');
  assert.equal(info.algorithm, 'ES256');
  const key = createPublicKey({ key: info.spki, format: 'der', type: 'spki' });
  assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');

  const file = path.join(dir, `${keyId}.sekey`);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
});

test('finds it again with the same public key', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  const a = await ks.findKey(keyId);
  const b = await ks.findKey(keyId);
  assert.ok(a);
  assert.deepEqual(a.spki, b.spki);
  await assert.rejects(ks.createKey({ keyId, requireUserPresence: false }), { code: 'E_EXISTS' });
});

test('signs with DER output that OpenSSL verifies', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  const info = await ks.findKey(keyId);
  const message = Buffer.from('v1|sign_receipt|bm9uY2U|42|' + 'ab'.repeat(32));
  const signature = await ks.sign(keyId, message, 'run the Secure Enclave tests');
  const key = createPublicKey({ key: info.spki, format: 'der', type: 'spki' });
  assert.ok(verify('sha256', message, { key, dsaEncoding: 'der' }, signature));
});

test('the private key is not exportable', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  assert.equal(await ks._probeExportable(keyId), false);
});

test('deleting removes the key file', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  await ks.deleteKey(keyId);
  assert.equal(await ks.findKey(keyId), null);
  assert.deepEqual(readdirSync(dir), []);
});

test('rejects a relative key directory', () => {
  assert.throws(() => ks.configure({ keyDirectory: 'relative/keys' }), TypeError);
});

test('seals and opens agent tokens with the Secure Enclave', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  assert.equal(ks.sealingAvailable(), true);
  const token = Buffer.from('agent-token-' + randomBytes(16).toString('base64url'));
  const a = ks.sealData(token);
  const b = ks.sealData(token);
  assert.notDeepEqual(a, b, 'each seal uses a fresh ephemeral key');
  assert.ok(!a.includes(token), 'the token must not appear in the sealed data');
  assert.deepEqual(ks.openData(a), token);
  assert.deepEqual(ks.openData(b), token);

  const tampered = Buffer.from(a);
  tampered[tampered.length - 1] ^= 0x01;
  assert.throws(() => ks.openData(tampered), { code: 'E_INTERNAL' });
  assert.equal(statSync(path.join(dir, '_token-seal.sekey')).mode & 0o777, 0o600);
});

// Keys imported from a .p12 (certificate-password-pairing-plan.md §6.1): encrypted
// with the certificate password inside a layer sealed to a Secure Enclave key
// that needs no presence, kept as <keyId>.p12key. No prompt.
const certKeyId = `ds.test.cert.${randomBytes(6).toString('hex')}`;
const fixture = (name) => readFileSync(new URL(`../../test/fixtures/pkcs12/${name}`, import.meta.url));

for (const [file, algorithm] of [
  ['rsa2048-legacy.p12', 'RS256'],
  ['p256.p12', 'ES256'],
]) {
  test(`imports ${file} sealed by the Secure Enclave, and signs`, async (t) => {
    if (!hardware) return t.skip('no Secure Enclave available');
    if (!(await ks.capabilities()).pkcs12) return t.skip('PKCS#12 import needs macOS 15');
    const imported = await ks.importPkcs12({
      keyId: certKeyId,
      data: fixture(file),
      password: 'test',
    });
    try {
      assert.equal(imported.key.protection, 'software');
      assert.equal(imported.key.algorithm, algorithm);
      const leafSpki = new X509Certificate(imported.chain[0]).publicKey.export({ format: 'der', type: 'spki' });
      assert.deepEqual(imported.key.spki, leafSpki);

      const sealedFile = path.join(dir, `${certKeyId}.p12key`);
      assert.equal(statSync(sealedFile).mode & 0o777, 0o600);
      assert.equal(readFileSync(sealedFile)[5], 1, 'outer layer: Secure Enclave');
      assert.equal(await ks._probeExportable(certKeyId), false);

      const found = await ks.findKey(certKeyId);
      assert.deepEqual(found.spki, leafSpki);
      assert.equal(found.userPresence, true, 'the password approves each use');

      const message = Buffer.from('v1|sign_receipt|bm9uY2U|42|' + 'cd'.repeat(32));
      await assert.rejects(ks.sign(certKeyId, message, 'run the certificate tests', undefined, 'wrong'), {
        code: 'E_BAD_PASSWORD',
      });
      const signature = await ks.sign(certKeyId, message, 'run the certificate tests', undefined, 'test');
      const key = createPublicKey({ key: leafSpki, format: 'der', type: 'spki' });
      const ok =
        algorithm === 'ES256'
          ? verify('sha256', message, { key, dsaEncoding: 'der' }, signature)
          : verify('sha256', message, key, signature);
      assert.ok(ok);
      await assert.rejects(
        ks.importPkcs12({ keyId: certKeyId, data: fixture(file), password: 'test' }),
        { code: 'E_EXISTS' },
      );
    } finally {
      await ks.deleteKey(certKeyId);
    }
    assert.equal(await ks.findKey(certKeyId), null);
    assert.ok(!readdirSync(dir).some((f) => f.startsWith(certKeyId)));
  });
}

test('a tampered .p12key fails to unseal', async (t) => {
  if (!hardware) return t.skip('no Secure Enclave available');
  if (!(await ks.capabilities()).pkcs12) return t.skip('PKCS#12 import needs macOS 15');
  const id = `${certKeyId}.tamper`;
  await ks.importPkcs12({ keyId: id, data: fixture('rsa2048-aes.p12'), password: 'test' });
  try {
    const file = path.join(dir, `${id}.p12key`);
    const bytes = readFileSync(file);
    bytes[bytes.length - 1] ^= 0x01;
    writeFileSync(file, bytes);
    // The Secure Enclave layer fails: damage, not a wrong password.
    await assert.rejects(ks.sign(id, Buffer.from('x'), 'test', undefined, 'test'), { code: 'E_INTERNAL' });
  } finally {
    await ks.deleteKey(id);
  }
});
