// Device-code pairing (desktop-agent-plan.md §8.1; docs: #/how-the-api-works).
//
//   lookup(code) → create identity + session keys → sign register_agent proof
//   (Touch ID / Hello) → claim → poll until the user confirms on the web.
//
// Each pairing gets fresh keys under a new key id, so a failed re-pair never
// breaks the existing pairing; the old keys are deleted only after success.
//
// One signature per app per computer (multi-app-pairing-plan.md §1.1), and
// one computer per account (one-computer-per-account-plan.md): right after
// the lookup, before any key or OS prompt, pairing stops if this computer
// already holds a different account's signature for the app, if the account
// is already paired with another computer, or if the server doesn't allow
// this kind of device. The server enforces all three again at claim; these
// checks just fail early and explain why.
import { randomBytes } from 'node:crypto';

import { ApiError, type AgentApi, type PairingLookup } from './api';
import { canonicalMessage, registrationPayloadHash, sha256Hex } from './canonical';
import { detectDeviceType, isDeviceType, type DeviceType } from './device-type';
import type { KeyInfo, KeyStore } from './keystore';
import type { PairedServer, Store } from './store';

export type PairingProgress =
  | { stage: 'looking_up' }
  /** This computer already holds this account's signature for the app; waiting for confirmRepair. */
  | { stage: 'already_paired_locally'; serverName: string; userName: string }
  | { stage: 'creating_keys'; serverName: string }
  | {
      stage: 'awaiting_confirmation';
      serverName: string;
      origin: string;
      deviceLabel: string;
      /** Set when the server will update this computer's existing device instead of adding one. */
      existingDevice?: { label: string; deviceType?: DeviceType };
    }
  | { stage: 'paired'; server: PairedServer; rebound: boolean };

export type PairingErrorCode =
  | 'origin_mismatch'
  | 'invalid_response'
  | 'presence_unavailable'
  | 'rejected'
  | 'expired'
  | 'aborted'
  | 'app_already_paired'
  | 'machine_already_paired'
  | 'account_already_paired'
  | 'device_type_not_allowed';

export class PairingError extends Error {
  constructor(
    readonly code: PairingErrorCode,
    message: string,
    /** The pairing in the way, for app_already_paired: the UI offers to unpair it. */
    readonly serverId?: string,
    /** For account_already_paired: the web page where the other computer can be removed. */
    readonly manageUrl?: string,
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
  /**
   * The same account is already paired for this app: resolve true to re-pair
   * with new keys, false to stop before anything is created. Without it,
   * re-pairing goes ahead.
   */
  confirmRepair?: (existing: PairedServer) => Promise<boolean>;
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
  const userId = String(lookup.user_id);

  const device = await keystore.deviceInfo(server.salt);
  const deviceType = detectDeviceType(device);
  if (Array.isArray(lookup.blocked_device_types) && lookup.blocked_device_types.includes(deviceType)) {
    throw blockedError(deviceType, server.name);
  }

  const existing = store.get(server.id);
  if (existing && existing.userId !== userId) throw alreadyPairedError(existing);

  const manageUrl = devicesUrl(lookup.devices_url, api.origin);
  const computer = lookup.agent_device;
  // This install's own pairing for the account can prove it's the same
  // computer at claim (rebind proof), whatever the hardware hash says.
  const ownDevice = !!existing && existing.deviceUuid === computer?.uuid;
  if (computer && !ownDevice && !sameComputer(computer.hardware_id_hash, device.hardwareIdHash)) {
    throw accountPairedError(server.name, lookup.user_name, computer.label, manageUrl);
  }

  if (existing) {
    progress({ stage: 'already_paired_locally', serverName: server.name, userName: existing.userName });
    const repair = opts.confirmRepair ? await opts.confirmRepair(existing) : true;
    if (!repair || opts.signal?.aborted) throw new PairingError('aborted', 'Pairing was cancelled.');
  }

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

    const attestation = await keystore.attest(identityKeyId).catch(() => null);
    const message = canonicalMessage(
      'register_agent',
      lookup.nonce,
      lookup.user_id,
      registrationPayloadHash(identity.spki, session.spki),
    );
    opts.signal?.throwIfAborted();
    const proof = await keystore.sign(identityKeyId, Buffer.from(message, 'utf8'), `pair this computer with ${server.name}`);
    const rebind = existing ? await rebindProof(keystore, existing, lookup, identity.spki, session.spki) : null;

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
        hardware_id_hash: device.hardwareIdHash || null,
        device_type: deviceType,
        chassis_type: device.chassisType,
        virtual: device.virtual,
      },
      agent_version: deps.agentVersion,
      proof: proof.toString('base64'),
      replaces: rebind,
    }).catch((err: unknown) => {
      throw fromClaimError(err, server.name, deviceType, lookup.user_name, manageUrl);
    });

    const replaces = claim.existing_device;
    progress({
      stage: 'awaiting_confirmation',
      serverName: server.name,
      origin: api.origin,
      deviceLabel: device.hostname || device.model,
      existingDevice: replaces?.label
        ? { label: replaces.label, deviceType: isDeviceType(replaces.device_type) ? replaces.device_type : undefined }
        : undefined,
    });

    const deadline = Date.parse(lookup.expires_at) || Date.now() + 10 * 60_000;
    for (;;) {
      if (opts.signal?.aborted) throw new PairingError('aborted', 'Pairing was cancelled.');
      if (Date.now() > deadline) throw new PairingError('expired', 'The pairing code expired. Start again on the web.');

      const result = await api.pollPairing(lookup.pairing, claim.poll_secret);
      if (result.status === 'confirmed') {
        const type = isDeviceType(result.device.device_type) ? result.device.device_type : deviceType;
        const paired = toPairedServer(lookup, api.origin, identity, identityKeyId, sessionKeyId, result.device, type);
        // Re-check: another pairing for this app may have finished meanwhile.
        const previous = store.get(server.id);
        if (previous && previous.userId !== userId) throw alreadyPairedError(previous);
        await store.save(paired, result.token);
        created.length = 0; // keys now belong to the saved pairing
        if (previous) await deleteKeys(keystore, [previous.identityKeyId, previous.sessionKeyId]);
        const rebound = result.rebound === true;
        progress({ stage: 'paired', server: paired, rebound });
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
  deviceType: DeviceType,
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
    deviceType,
  };
}

function alreadyPairedError(existing: PairedServer): PairingError {
  const holder = existing.userName ? `${existing.userName}'s` : "another account's";
  return new PairingError(
    'app_already_paired',
    `This computer already holds ${holder} signature for ${existing.name}. Unpair it first to pair a different account.`,
    existing.id,
  );
}

/**
 * The existing pairing's session key signs the new keys: only the computer
 * holding that key (Secure Enclave / TPM, not exportable) can, so the server
 * may rebind its device even with no or a changed hardware id. No OS prompt.
 * Best effort: without it the server falls back to the hardware hash.
 */
async function rebindProof(
  keystore: KeyStore,
  existing: PairedServer,
  lookup: PairingLookup,
  identitySpki: Buffer,
  sessionSpki: Buffer,
): Promise<{ device_uuid: string; proof: string } | null> {
  try {
    const message = canonicalMessage('rebind_agent', lookup.nonce, lookup.user_id, registrationPayloadHash(identitySpki, sessionSpki));
    const proof = await keystore.sign(existing.sessionKeyId, Buffer.from(message, 'utf8'), 'authenticate with the server');
    return { device_uuid: existing.deviceUuid, proof: proof.toString('base64') };
  } catch {
    return null;
  }
}

/** Only matching hashes prove it's the same computer; a missing one proves nothing. */
function sameComputer(a: string | null | undefined, b: string | null | undefined): boolean {
  return !!a && !!b && a === b;
}

/** The server's devices page, only if it's on the server's own origin. */
function devicesUrl(url: string | undefined, origin: string): string {
  try {
    if (url && new URL(url).origin === origin) return url;
  } catch {
    // fall through
  }
  return origin;
}

function accountPairedError(serverName: string, userName: string | undefined, label: unknown, manageUrl: string): PairingError {
  const computer = typeof label === 'string' && label.trim() ? label.trim() : 'another computer';
  const whose = userName ? `${userName}'s` : 'Your';
  return new PairingError(
    'account_already_paired',
    `Your account is already paired with another computer. ${whose} ${serverName} signature is on ${computer}. ` +
      'One account can be paired with only one computer. ' +
      `To use this computer instead, remove ${computer} from My signing devices on the web, then pair again.`,
    undefined,
    manageUrl,
  );
}

function blockedError(deviceType: DeviceType, serverName: string): PairingError {
  return new PairingError(
    'device_type_not_allowed',
    deviceType === 'virtual_machine'
      ? `Pairing from a virtual machine isn't allowed on ${serverName}. Install the agent on the computer itself.`
      : `${serverName} doesn't allow pairing from this kind of device.`,
  );
}

/** The server's refusals at claim, in the same words as the local checks. */
function fromClaimError(
  err: unknown,
  serverName: string,
  deviceType: DeviceType,
  userName: string | undefined,
  manageUrl: string,
): unknown {
  if (!(err instanceof ApiError)) return err;
  if (err.code === 'account_already_paired') {
    const device = err.details.device as { label?: unknown } | undefined;
    return accountPairedError(serverName, userName, device?.label, manageUrl);
  }
  if (err.code === 'machine_already_paired') {
    return new PairingError(
      'machine_already_paired',
      `${serverName} says this computer is already paired with another account. ` +
        "Remove it from that account's signing devices on the web, or ask an admin to release it.",
    );
  }
  if (err.code === 'device_type_not_allowed') return blockedError(deviceType, serverName);
  return err;
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
