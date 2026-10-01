// Device-code pairing (desktop-agent-plan.md §8.1; docs: #/how-the-api-works).
//
//   lookup(code) → create identity + session keys → sign register_agent proof
//   (Touch ID / Hello) → claim → poll until the user confirms on the web.
//
// Each pairing gets fresh keys under a new key id, so a failed re-pair never
// breaks the existing pairing; the old keys are deleted only after success.
import { randomBytes } from 'node:crypto';

import type { AgentApi, PairingLookup } from './api';
import { canonicalMessage, registrationPayloadHash, sha256Hex } from './canonical';
import type { KeyInfo, KeyStore } from './keystore';
import type { PairedServer, Store } from './store';

export type PairingProgress =
  | { stage: 'looking_up' }
  | { stage: 'creating_keys'; serverName: string }
  | { stage: 'awaiting_confirmation'; serverName: string; origin: string; deviceLabel: string }
  | { stage: 'paired'; server: PairedServer };

export class PairingError extends Error {
  constructor(
    readonly code:
      | 'origin_mismatch'
      | 'invalid_response'
      | 'presence_unavailable'
      | 'rejected'
      | 'expired'
      | 'aborted',
    message: string,
  ) {
    super(message);
  }
}

export interface PairingDeps {
  keystore: KeyStore;
  store: Store;
  api: AgentApi;
  agentVersion: string;
  /** macOS: require biometrics instead of "biometrics or password". */
  biometryOnly?: boolean;
  pollIntervalMs?: number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

export interface PairOptions {
  onProgress?: (p: PairingProgress) => void;
  signal?: AbortSignal;
}

const SERVER_ID = /^[A-Za-z0-9_-]{1,64}$/;

export async function pair(deps: PairingDeps, code: string, opts: PairOptions = {}): Promise<PairedServer> {
  const { keystore, store, api } = deps;
  const progress = opts.onProgress ?? (() => {});
  const sleep = deps.sleep ?? abortableSleep;

  progress({ stage: 'looking_up' });
  const lookup = await api.lookupPairing(code);
  validateLookup(lookup, api.origin);
  const server = lookup.server;
  progress({ stage: 'creating_keys', serverName: server.name });

  const prefix = `ds.${sha256Hex(`${api.origin}|${server.id}`).slice(0, 16)}.${randomBytes(4).toString('hex')}`;
  const identityKeyId = `${prefix}.identity`;
  const sessionKeyId = `${prefix}.session`;
  const created: string[] = [];

  try {
    const identity = await keystore.createKey({
      keyId: identityKeyId,
      requireUserPresence: true,
      biometryOnly: deps.biometryOnly,
    });
    created.push(identityKeyId);
    const session = await keystore.createKey({ keyId: sessionKeyId, requireUserPresence: false });
    created.push(sessionKeyId);

    if (lookup.require_presence && !identity.userPresence) {
      throw new PairingError(
        'presence_unavailable',
        'This computer cannot enforce Touch ID or Windows Hello, which this server requires.',
      );
    }
    if (session.algorithm !== 'ES256') throw new Error('the session key must be ES256');

    const device = await keystore.deviceInfo(server.salt);
    const attestation = await keystore.attest(identityKeyId).catch(() => null);
    const message = canonicalMessage(
      'register_agent',
      lookup.nonce,
      lookup.user_id,
      registrationPayloadHash(identity.spki, session.spki),
    );
    opts.signal?.throwIfAborted();
    const proof = await keystore.sign(identityKeyId, Buffer.from(message, 'utf8'), `pair this computer with ${server.name}`);

    const claim = await api.claimPairing(lookup.pairing, {
      user_code: code,
      algorithm: identity.algorithm,
      identity_public_key: identity.spki.toString('base64'),
      session_public_key: session.spki.toString('base64'),
      protection: identity.protection,
      user_presence: identity.userPresence,
      attestation: attestation
        ? {
            format: attestation.format,
            statement: attestation.statement.toString('base64'),
            chain: attestation.chain.map((c) => c.toString('base64')),
          }
        : null,
      device: {
        platform: device.platform,
        os_version: device.osVersion,
        model: device.model,
        model_identifier: device.modelIdentifier,
        form_factor: device.formFactor,
        label: device.hostname || device.model,
        hardware_id_hash: device.hardwareIdHash,
      },
      agent_version: deps.agentVersion,
      proof: proof.toString('base64'),
    });

    progress({
      stage: 'awaiting_confirmation',
      serverName: server.name,
      origin: api.origin,
      deviceLabel: device.hostname || device.model,
    });

    const deadline = Date.parse(lookup.expires_at) || Date.now() + 10 * 60_000;
    for (;;) {
      if (opts.signal?.aborted) throw new PairingError('aborted', 'Pairing was cancelled.');
      if (Date.now() > deadline) throw new PairingError('expired', 'The pairing code expired. Start again on the web.');

      const result = await api.pollPairing(lookup.pairing, claim.poll_secret);
      if (result.status === 'confirmed') {
        const paired = toPairedServer(lookup, api.origin, identity, identityKeyId, sessionKeyId, result.device);
        const previous = store.get(server.id);
        await store.save(paired, result.token);
        created.length = 0; // keys now belong to the saved pairing
        if (previous) await deleteKeys(keystore, [previous.identityKeyId, previous.sessionKeyId]);
        progress({ stage: 'paired', server: paired });
        return paired;
      }
      if (result.status === 'rejected') throw new PairingError('rejected', 'Pairing was declined on the web.');
      if (result.status === 'expired') throw new PairingError('expired', 'The pairing code expired. Start again on the web.');

      await sleep(deps.pollIntervalMs ?? 2000, opts.signal);
    }
  } finally {
    await deleteKeys(keystore, created);
  }
}

function validateLookup(lookup: PairingLookup, origin: string): void {
  const s = lookup?.server;
  if (!s || typeof s.id !== 'string' || !SERVER_ID.test(s.id) || typeof s.name !== 'string' || typeof s.salt !== 'string') {
    throw new PairingError('invalid_response', 'The server sent an invalid pairing response.');
  }
  // The server must describe itself with the origin we're talking to.
  if (s.origin !== origin) {
    throw new PairingError(
      'origin_mismatch',
      `The server's address is ${s.origin}, not ${origin}. Use that address or fix APP_URL.`,
    );
  }
  if (typeof lookup.pairing !== 'string' || typeof lookup.nonce !== 'string' || lookup.user_id == null) {
    throw new PairingError('invalid_response', 'The server sent an invalid pairing response.');
  }
}

function toPairedServer(
  lookup: PairingLookup,
  origin: string,
  identity: KeyInfo,
  identityKeyId: string,
  sessionKeyId: string,
  device: { uuid: string; label: string },
): PairedServer {
  return {
    id: lookup.server.id,
    name: lookup.server.name,
    origin,
    salt: lookup.server.salt,
    userId: String(lookup.user_id),
    userName: lookup.user_name ?? '',
    deviceUuid: device.uuid,
    deviceLabel: device.label,
    identityKeyId,
    sessionKeyId,
    algorithm: identity.algorithm,
    protection: identity.protection,
    userPresence: identity.userPresence,
    pairedAt: new Date().toISOString(),
  };
}

export async function deleteKeys(keystore: KeyStore, keyIds: string[]): Promise<void> {
  for (const keyId of keyIds) {
    await keystore.deleteKey(keyId).catch(() => {});
  }
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}
