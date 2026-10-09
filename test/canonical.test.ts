import { describe, expect, it } from 'vitest';

import { canonicalMessage, registrationPayloadHash, requestPayloadHash } from '../src/main/canonical';
import vectors from './fixtures/canonical-vectors.json';

describe('canonical messages (shared vectors)', () => {
  it.each(vectors.messages)('builds $purpose exactly', (v) => {
    expect(canonicalMessage(v.purpose, v.nonce, v.user_id, v.payload_hash)).toBe(v.message);
  });

  it.each(vectors.requests)('hashes request $method $path', (v) => {
    expect(requestPayloadHash(v.method, v.path, v.body, v.timestamp)).toBe(v.payload_hash);
  });

  it.each(vectors.registrations)('hashes both registration public keys', (v) => {
    const hash = registrationPayloadHash(Buffer.from(v.identity_spki, 'base64'), Buffer.from(v.session_spki, 'base64'));
    expect(hash).toBe(v.payload_hash);
  });

  it.each(vectors.invalid)('rejects: $why', (v) => {
    expect(() => canonicalMessage(v.purpose, v.nonce, v.user_id, v.payload_hash)).toThrow();
  });

  it('covers the hub purposes', () => {
    expect(vectors.messages.map((v) => v.purpose)).toEqual(expect.arrayContaining(['login', 'transfer']));
  });

  it('accepts numeric user ids', () => {
    expect(canonicalMessage('sign_receipt', 'abc', 42, 'a'.repeat(64))).toBe(`v1|sign_receipt|abc|42|${'a'.repeat(64)}`);
  });
});
