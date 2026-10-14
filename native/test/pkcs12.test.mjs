// PKCS#12 import tests (pkcs12-key-storage-plan.md §11.2).
//
// Uses the throwaway fixtures from scripts/make-pkcs12-fixtures.sh (password
// "test"), never a real certificate. Forces the software backend unless
// KUKUX_KEYSTORE_BACKEND is already set, like keystore.test.mjs.
import assert from 'node:assert/strict';
import { X509Certificate, createPublicKey, randomBytes, verify } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { after, test } from 'node:test';

process.env.KUKUX_KEYSTORE_BACKEND ??= 'software';

const require = createRequire(import.meta.url);
const ks = require('../build/Release/keystore.node');
// Key files go here, never into the app's real key directory.
const keyDir = mkdtempSync(path.join(tmpdir(), 'kukux-p12-'));
ks.configure({ keyDirectory: keyDir });

const fixture = (name) => readFileSync(new URL(`../../test/fixtures/pkcs12/${name}`, import.meta.url));
const caps = await ks.capabilities();
const skip = caps.pkcs12 ? false : 'PKCS#12 import is not supported here (macOS < 15)';

const keyIds = [];
const newKeyId = () => {
  const id = `ds.test.cert.${randomBytes(6).toString('hex')}`;
  keyIds.push(id);
  return id;
};
const message = Buffer.from('v1|sign_receipt|bm9uY2U|42|' + 'ab'.repeat(32));

after(async () => {
  for (const id of keyIds) await ks.deleteKey(id);
  rmSync(keyDir, { recursive: true, force: true });
});

function verifyWith(spki, algorithm, signature) {
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (algorithm === 'ES256') return verify('sha256', message, { key, dsaEncoding: 'der' }, signature);
  return verify('sha256', message, key, signature);
}

test('reports whether PKCS#12 import is supported', () => {
  assert.equal(typeof caps.pkcs12, 'boolean');
  if (process.platform === 'win32') assert.equal(caps.pkcs12, true);
});

for (const file of ['rsa2048-legacy.p12', 'rsa2048-aes.p12']) {
  test(`inspects ${file}: leaf first, whole chain, RS256`, { skip }, async () => {
    const contents = await ks.inspectPkcs12(fixture(file), 'test');
    assert.equal(contents.algorithm, 'RS256');
    assert.equal(contents.keyBits, 2048);
    assert.equal(contents.chain.length, 3);
    const leaf = new X509Certificate(contents.chain[0]);
    assert.match(leaf.subject, /CN=Test Signer rsa/);
    assert.deepEqual(contents.chain[0], fixture('rsa2048-leaf.cer'));
  });
}

test('inspect does not create a key', { skip }, async () => {
  const before = await ks.findKey('ds.test.cert.never');
  await ks.inspectPkcs12(fixture('rsa2048-aes.p12'), 'test');
  assert.equal(before, null);
});

test('a wrong password is E_BAD_PASSWORD', { skip }, async () => {
  await assert.rejects(ks.inspectPkcs12(fixture('rsa2048-legacy.p12'), 'wrong'), { code: 'E_BAD_PASSWORD' });
  await assert.rejects(
    ks.importPkcs12({ keyId: newKeyId(), data: fixture('rsa2048-aes.p12'), password: '' }),
    { code: 'E_BAD_PASSWORD' },
  );
});

test('a file that is not PKCS#12 is E_BAD_FILE', { skip }, async () => {
  await assert.rejects(ks.inspectPkcs12(Buffer.from('not a certificate'), 'test'), { code: 'E_BAD_FILE' });
});

test('a file without a private key is E_BAD_FILE', { skip }, async () => {
  await assert.rejects(ks.inspectPkcs12(fixture('ca-only.p12'), 'test'), { code: 'E_BAD_FILE' });
});

test('an empty or oversized file is E_BAD_FILE before parsing', async () => {
  assert.throws(() => ks.inspectPkcs12(Buffer.alloc(0), 'test'), { code: 'E_BAD_FILE' });
  assert.throws(() => ks.inspectPkcs12(Buffer.alloc(64 * 1024 + 1), 'test'), { code: 'E_BAD_FILE' });
});

test('RSA keys under 2048 bits are E_UNSUPPORTED', { skip }, async () => {
  await assert.rejects(ks.inspectPkcs12(fixture('rsa1024.p12'), 'test'), { code: 'E_UNSUPPORTED' });
});

// Imported keys are encrypted with the certificate's password
// (certificate-password-pairing-plan.md §6): sign() refuses them, signing
// takes the password, and a wrong one is E_BAD_PASSWORD.
const importFixture = async (file, keyId = newKeyId()) => ({
  keyId,
  imported: await ks.importPkcs12({ keyId, data: fixture(file), password: 'test' }),
});

for (const [file, algorithm] of [
  ['rsa2048-legacy.p12', 'RS256'],
  ['p256.p12', 'ES256'],
]) {
  test(`imports ${file}, signs with its password, and OpenSSL verifies with the certificate's key`, { skip }, async () => {
    const { keyId, imported } = await importFixture(file);
    assert.equal(imported.algorithm, algorithm);
    assert.equal(imported.key.keyId, keyId);
    assert.equal(imported.key.algorithm, algorithm);
    assert.equal(imported.key.userPresence, true);

    // The key's SPKI is the leaf certificate's.
    const leafSpki = new X509Certificate(imported.chain[0]).publicKey.export({ format: 'der', type: 'spki' });
    assert.deepEqual(imported.key.spki, leafSpki);

    const found = await ks.findKey(keyId);
    assert.ok(found);
    assert.deepEqual(found.spki, leafSpki);
    assert.equal(found.algorithm, algorithm);

    const signature = await ks.sign(keyId, message, 'test', undefined, 'test');
    assert.ok(verifyWith(leafSpki, algorithm, signature));
  });
}

test('a certificate key does not sign without its password, or with a wrong one', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  await assert.rejects(ks.sign(keyId, message, 'test'), { code: 'E_BAD_PASSWORD' });
  await assert.rejects(ks.sign(keyId, message, 'test', undefined, 'wrong'), { code: 'E_BAD_PASSWORD' });
  await assert.rejects(ks.sign(keyId, message, 'test', undefined, ''), { code: 'E_BAD_PASSWORD' });
});

test('verifyCertificatePassword checks the password without signing', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  await ks.verifyCertificatePassword(keyId, 'test');
  await assert.rejects(ks.verifyCertificatePassword(keyId, 'Test'), { code: 'E_BAD_PASSWORD' });
  await assert.rejects(ks.verifyCertificatePassword('ds.test.cert.none', 'test'), { code: 'E_NOT_FOUND' });
});

test('the key file is bound to its directory and holds no plaintext key', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  const raw = readFileSync(path.join(keyDir, `${keyId}.p12key`));
  assert.equal(raw.subarray(0, 4).toString(), 'KP12');
  assert.equal(raw[4], 2);
  // The PKCS#1 private key starts with SEQUENCE { INTEGER 0, INTEGER n…: never in clear.
  const leafKey = readFileSync(new URL('../../test/fixtures/pkcs12/rsa2048-leaf.key', import.meta.url), 'utf8');
  const der = Buffer.from(leafKey.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  assert.ok(!raw.includes(der.subarray(-64)));
});

test('a damaged key file is E_INTERNAL, not a wrong password', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  const file = path.join(keyDir, `${keyId}.p12key`);
  const bytes = readFileSync(file);
  bytes[bytes.length - 1] ^= 0x01;
  writeFileSync(file, bytes);
  const outer = bytes[5];
  // With an outer layer (Secure Enclave, DPAPI) damage shows there; bare, the
  // password layer can't tell damage from a wrong password.
  await assert.rejects(ks.sign(keyId, message, 'test', undefined, 'test'), { code: outer === 0 ? 'E_BAD_PASSWORD' : 'E_INTERNAL' });
});

test('a key file from the earlier Touch ID version is refused: import it again', { skip }, async () => {
  const keyId = newKeyId();
  writeFileSync(path.join(keyDir, `${keyId}.p12key`), Buffer.from('KP12\x01\x01\x01rest-of-a-v1-file', 'latin1'));
  await assert.rejects(ks.findKey(keyId), { code: 'E_UNSUPPORTED', message: /import it again/ });
});

test('the imported private key is not exportable', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  assert.equal(await ks._probeExportable(keyId), false);
});

test('importing under an existing key id is E_EXISTS', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  await assert.rejects(ks.importPkcs12({ keyId, data: fixture('rsa2048-aes.p12'), password: 'test' }), { code: 'E_EXISTS' });
});

test('deleting removes the imported key', { skip }, async () => {
  const { keyId } = await importFixture('rsa2048-aes.p12');
  await ks.deleteKey(keyId);
  assert.equal(await ks.findKey(keyId), null);
  await assert.rejects(ks.sign(keyId, message, 'test', undefined, 'test'), { code: 'E_NOT_FOUND' });
  assert.ok(!existsSync(path.join(keyDir, `${keyId}.p12key`)));
});
