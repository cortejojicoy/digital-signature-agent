// PKCS#12 import tests (pkcs12-key-storage-plan.md §11.2).
//
// Uses the throwaway fixtures from scripts/make-pkcs12-fixtures.sh (password
// "test"), never a real certificate. Forces the software backend unless
// KUKUX_KEYSTORE_BACKEND is already set, like keystore.test.mjs.
import assert from 'node:assert/strict';
import { X509Certificate, createPublicKey, randomBytes, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { after, test } from 'node:test';

process.env.KUKUX_KEYSTORE_BACKEND ??= 'software';

const require = createRequire(import.meta.url);
const ks = require('../build/Release/keystore.node');

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
    ks.importPkcs12({ keyId: newKeyId(), data: fixture('rsa2048-aes.p12'), password: '', requireUserPresence: false }),
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

// Without a Secure Enclave, macOS keeps imported keys in the legacy keychain,
// which only takes RSA ones.
const macKeychain = process.platform === 'darwin' && process.env.KUKUX_KEYSTORE_BACKEND === 'software';

test('P-256 certificates are E_UNSUPPORTED in the macOS legacy keychain', { skip: skip || !macKeychain }, async () => {
  await assert.rejects(
    ks.importPkcs12({ keyId: newKeyId(), data: fixture('p256.p12'), password: 'test', requireUserPresence: false }),
    { code: 'E_UNSUPPORTED' },
  );
});

for (const [file, algorithm] of [
  ['rsa2048-legacy.p12', 'RS256'],
  ['p256.p12', 'ES256'],
]) {
  const unsupported = algorithm === 'ES256' && macKeychain;
  test(`imports ${file}, signs, and OpenSSL verifies with the certificate's key`, { skip: skip || unsupported }, async () => {
    const keyId = newKeyId();
    const imported = await ks.importPkcs12({ keyId, data: fixture(file), password: 'test', requireUserPresence: false });
    assert.equal(imported.algorithm, algorithm);
    assert.equal(imported.key.keyId, keyId);
    assert.equal(imported.key.algorithm, algorithm);

    // The key's SPKI is the leaf certificate's.
    const leafSpki = new X509Certificate(imported.chain[0]).publicKey.export({ format: 'der', type: 'spki' });
    assert.deepEqual(imported.key.spki, leafSpki);

    const found = await ks.findKey(keyId);
    assert.ok(found);
    assert.deepEqual(found.spki, leafSpki);
    assert.equal(found.algorithm, algorithm);

    const signature = await ks.sign(keyId, message, 'test');
    assert.ok(verifyWith(leafSpki, algorithm, signature));
  });
}

test('the imported private key is not exportable', { skip }, async () => {
  const keyId = newKeyId();
  await ks.importPkcs12({ keyId, data: fixture('rsa2048-aes.p12'), password: 'test', requireUserPresence: false });
  assert.equal(await ks._probeExportable(keyId), false);
});

test('importing under an existing key id is E_EXISTS', { skip }, async () => {
  const keyId = newKeyId();
  await ks.importPkcs12({ keyId, data: fixture('rsa2048-aes.p12'), password: 'test', requireUserPresence: false });
  await assert.rejects(
    ks.importPkcs12({ keyId, data: fixture('rsa2048-aes.p12'), password: 'test', requireUserPresence: false }),
    { code: 'E_EXISTS' },
  );
});

test('deleting removes the imported key', { skip }, async () => {
  const keyId = newKeyId();
  await ks.importPkcs12({ keyId, data: fixture('rsa2048-aes.p12'), password: 'test', requireUserPresence: false });
  await ks.deleteKey(keyId);
  assert.equal(await ks.findKey(keyId), null);
  await assert.rejects(ks.sign(keyId, message, 'test'), { code: 'E_NOT_FOUND' });
});
