// Native key store tests (desktop-agent-plan.md §12).
//
// CI runners have no Secure Enclave, TPM or Hello, so these force the software
// backend unless KUKUX_KEYSTORE_BACKEND is already set. Run on real hardware
// with KUKUX_KEYSTORE_BACKEND=auto to exercise the hardware path.
import assert from 'node:assert/strict';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { createRequire } from 'node:module';
import { after, test } from 'node:test';

process.env.KUKUX_KEYSTORE_BACKEND ??= 'software';

const require = createRequire(import.meta.url);
const ks = require('../build/Release/keystore.node');

const keyId = `ds.test.${randomBytes(6).toString('hex')}`;
const message = Buffer.from('v1|sign_receipt|bm9uY2U|42|' + 'ab'.repeat(32));

after(async () => {
  await ks.deleteKey(keyId);
});

function verifySignature(info, data, signature) {
  const key = createPublicKey({ key: info.spki, format: 'der', type: 'spki' });
  if (info.algorithm === 'ES256') {
    // DER-encoded ECDSA, exactly what PHP's openssl_verify expects.
    return verify('sha256', data, { key, dsaEncoding: 'der' }, signature);
  }
  return verify('sha256', data, key, signature);
}

test('reports capabilities', async () => {
  const caps = await ks.capabilities();
  assert.equal(typeof caps.hardware, 'boolean');
  assert.equal(typeof caps.userPresence, 'boolean');
  assert.equal(typeof caps.attestation, 'boolean');
});

test('creates a key with a valid SPKI', async () => {
  const info = await ks.createKey({ keyId, requireUserPresence: false });
  assert.equal(info.keyId, keyId);
  assert.ok(['ES256', 'RS256'].includes(info.algorithm));
  assert.ok(['secure_enclave', 'tpm', 'software'].includes(info.protection));
  const key = createPublicKey({ key: info.spki, format: 'der', type: 'spki' });
  assert.equal(key.asymmetricKeyType, info.algorithm === 'ES256' ? 'ec' : 'rsa');
  if (info.algorithm === 'ES256') assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');
});

test('refuses to create a duplicate key', async () => {
  await assert.rejects(ks.createKey({ keyId, requireUserPresence: false }), { code: 'E_EXISTS' });
});

test('finds the key again with the same public key', async () => {
  const found = await ks.findKey(keyId);
  assert.ok(found);
  const again = await ks.findKey(keyId);
  assert.deepEqual(found.spki, again.spki);
});

test('returns null for an unknown key', async () => {
  assert.equal(await ks.findKey('ds.test.does-not-exist'), null);
});

test('signs the message (not a digest) and OpenSSL verifies it', async () => {
  const info = await ks.findKey(keyId);
  const signature = await ks.sign(keyId, message, 'run the key store tests');
  assert.ok(Buffer.isBuffer(signature));
  assert.ok(verifySignature(info, message, signature), 'signature must verify');
  assert.ok(!verifySignature(info, Buffer.concat([message, Buffer.from('x')]), signature));
});

test('signing with an unknown key fails with E_NOT_FOUND', async () => {
  await assert.rejects(ks.sign('ds.test.does-not-exist', message, 'test'), { code: 'E_NOT_FOUND' });
});

test('the private key is not exportable', async () => {
  assert.equal(await ks._probeExportable(keyId), false);
});

test('rejects malformed key ids before touching the store', () => {
  assert.throws(() => ks.findKey('../etc/passwd'), TypeError);
  assert.throws(() => ks.findKey(''), TypeError);
});

test('reports device info with a salted hardware hash', async () => {
  const a = await ks.deviceInfo('server-a');
  const b = await ks.deviceInfo('server-b');
  assert.ok(['macos', 'windows'].includes(a.platform));
  assert.ok(['laptop', 'desktop', 'unknown'].includes(a.formFactor));
  assert.ok(a.model.length > 0);
  if (a.hardwareIdHash) {
    assert.match(a.hardwareIdHash, /^[0-9a-f]{64}$/);
    assert.notEqual(a.hardwareIdHash, b.hardwareIdHash, 'hash must not link across servers');
  }
  // Device-type inputs (multi-app-pairing-plan.md §4.2–4.3).
  assert.equal(typeof a.virtual, 'boolean');
  if (a.platform === 'macos') {
    assert.equal(a.chassisType, null);
  } else if (a.chassisType !== null) {
    assert.ok(Number.isInteger(a.chassisType) && a.chassisType >= 1 && a.chassisType <= 127);
  }
});

test('deletes the key', async () => {
  await ks.deleteKey(keyId);
  assert.equal(await ks.findKey(keyId), null);
});
