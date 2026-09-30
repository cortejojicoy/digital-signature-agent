// Software KeyStore for tests: same contract as native/keystore.node (DER
// ECDSA, PKCS#1 v1.5 RSA, SPKI DER), backed by node:crypto.
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import type { DeviceInfo, KeyInfo, KeyStore, Protection } from '../../src/main/keystore';

interface Entry {
  info: KeyInfo;
  privateKey: KeyObject;
}

export interface MemoryKeyStoreOptions {
  protection?: Protection;
  /** Whether presence-requiring keys actually get OS-enforced presence. */
  presence?: boolean;
  /** Use RSA for identity keys, like Windows Hello. */
  rsaIdentity?: boolean;
}

export class MemoryKeyStore implements KeyStore {
  readonly keys = new Map<string, Entry>();
  readonly prompts: string[] = [];
  /** Next sign() call with a presence key fails with E_CANCELLED. */
  cancelNextPrompt = false;

  constructor(private readonly options: MemoryKeyStoreOptions = {}) {}

  async capabilities() {
    return {
      hardware: this.options.protection !== 'software',
      userPresence: this.options.presence ?? true,
      attestation: false,
    };
  }

  async createKey(o: { keyId: string; requireUserPresence: boolean }): Promise<KeyInfo> {
    if (this.keys.has(o.keyId)) throw Object.assign(new Error('exists'), { code: 'E_EXISTS' });
    const rsa = o.requireUserPresence && this.options.rsaIdentity;
    const { privateKey, publicKey } = rsa
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const info: KeyInfo = {
      keyId: o.keyId,
      algorithm: rsa ? 'RS256' : 'ES256',
      spki: publicKey.export({ format: 'der', type: 'spki' }),
      protection: this.options.protection ?? 'secure_enclave',
      userPresence: o.requireUserPresence && (this.options.presence ?? true),
    };
    this.keys.set(o.keyId, { info, privateKey });
    return { ...info };
  }

  async findKey(keyId: string): Promise<KeyInfo | null> {
    const entry = this.keys.get(keyId);
    return entry ? { ...entry.info } : null;
  }

  async sign(keyId: string, message: Buffer, reason: string): Promise<Buffer> {
    const entry = this.keys.get(keyId);
    if (!entry) throw Object.assign(new Error('not found'), { code: 'E_NOT_FOUND' });
    if (entry.info.userPresence) {
      this.prompts.push(reason);
      if (this.cancelNextPrompt) {
        this.cancelNextPrompt = false;
        throw Object.assign(new Error('cancelled'), { code: 'E_CANCELLED' });
      }
    }
    if (entry.info.algorithm === 'RS256') return sign('sha256', message, entry.privateKey);
    return sign('sha256', message, { key: entry.privateKey, dsaEncoding: 'der' });
  }

  async attest() {
    return null;
  }

  async deleteKey(keyId: string): Promise<void> {
    this.keys.delete(keyId);
  }

  async deviceInfo(salt: string): Promise<DeviceInfo> {
    return {
      platform: 'macos',
      osVersion: '15.1.0',
      model: 'MacBook Pro',
      modelIdentifier: 'Mac15,3',
      formFactor: 'laptop',
      hostname: 'Juan’s MacBook Pro',
      hardwareIdHash: createHash('sha256').update(`${salt}TEST-UUID`).digest('hex'),
    };
  }
}
