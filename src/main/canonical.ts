// Canonical proof messages (desktop-agent-plan.md §8). Must stay byte-identical
// to the package's PHP builder; test/fixtures/canonical-vectors.json is the
// shared contract.
//
//   v1|<purpose>|<nonce_b64url>|<user_id>|<payload_hash_hex>
import { createHash } from 'node:crypto';

export type Purpose = 'register_agent' | 'rebind_agent' | 'sign_receipt' | 'login' | 'transfer' | 'request';

const PURPOSE = /^[a-z_]{1,64}$/;
const NONCE = /^[A-Za-z0-9_-]{1,128}$/;
const USER_ID = /^[^|\s]{1,64}$/;
const HASH = /^[0-9a-f]{64}$/;

export class CanonicalError extends Error {}

export function canonicalMessage(purpose: string, nonce: string, userId: string | number, payloadHash: string): string {
  const uid = String(userId);
  if (!PURPOSE.test(purpose)) throw new CanonicalError('purpose must match [a-z_]');
  if (!NONCE.test(nonce)) throw new CanonicalError('nonce must be base64url');
  if (!USER_ID.test(uid)) throw new CanonicalError('user_id must be non-empty and contain no "|" or whitespace');
  if (!HASH.test(payloadHash)) throw new CanonicalError('payload_hash must be 64 lowercase hex characters');
  return `v1|${purpose}|${nonce}|${uid}|${payloadHash}`;
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Payload for `register_agent` and `rebind_agent`: binds both new public keys to the pairing. */
export function registrationPayloadHash(identitySpki: Buffer, sessionSpki: Buffer): string {
  return sha256Hex(Buffer.concat([identitySpki, sessionSpki]));
}

/**
 * Payload for `request` proofs (§8.4). `path` includes the query string;
 * `body` is the exact bytes sent ("" for GET); `timestamp` is unix seconds.
 */
export function requestPayloadHash(method: string, path: string, body: string, timestamp: string | number): string {
  return sha256Hex(`${method.toUpperCase()}|${path}|${body}|${timestamp}`);
}
