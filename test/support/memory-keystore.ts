// Software KeyStore for tests: same contract as native/keystore.node (DER
// ECDSA, PKCS#1 v1.5 RSA, SPKI DER), backed by node:crypto.
import { X509Certificate, createHash, createPrivateKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import type { DeviceInfo, ImportedCertificate, KeyInfo, KeyStore, Pkcs12Contents, Protection } from '../../src/main/keystore';

/**
 * A .p12 the memory store "can open". node:crypto can't parse PKCS#12, so
 * tests register the file's bytes with the parts it holds.
 */
export interface FakePkcs12 {
  data: Buffer;
  password: string;
  chain: Buffer[];
  privateKey: KeyObject;
}

/** One of scripts/make-pkcs12-fixtures.sh's files, with its parts. */
export function fixturePkcs12(name: 'rsa2048-aes' | 'second'): FakePkcs12 {
  const dir = path.join(__dirname, '..', 'fixtures', 'pkcs12');
  const read = (file: string) => readFileSync(path.join(dir, file));
  const leaf = name === 'second' ? 'second-leaf' : 'rsa2048-leaf';
  return {
    data: read(`${name === 'second' ? 'second' : 'rsa2048-aes'}.p12`),
    password: 'test',
    chain: [read(`${leaf}.cer`), read('test-intermediate.cer'), read('test-root.cer')],
    privateKey: createPrivateKey(read(`${leaf}.key`)),
  };
}

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
  /** Overrides for what deviceInfo() reports, e.g. a VM or a Windows machine. */
  device?: Partial<DeviceInfo> & { hardwareUuid?: string };
  /** Files inspectPkcs12 / importPkcs12 can open. */
  pkcs12?: FakePkcs12[];
  /** capabilities().pkcs12; true by default. */
  pkcs12Supported?: boolean;
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
      pkcs12: this.options.pkcs12Supported ?? true,
    };
  }

  async inspectPkcs12(data: Buffer, password: string): Promise<Pkcs12Contents> {
    const file = this.openPkcs12(data, password);
    return { chain: [...file.chain], algorithm: 'RS256', keyBits: 2048 };
  }

  async importPkcs12(o: { keyId: string; data: Buffer; password: string; requireUserPresence: boolean }): Promise<ImportedCertificate> {
    const file = this.openPkcs12(o.data, o.password);
    if (this.keys.has(o.keyId)) throw Object.assign(new Error('exists'), { code: 'E_EXISTS' });
    const info: KeyInfo = {
      keyId: o.keyId,
      algorithm: 'RS256',
      spki: new X509Certificate(file.chain[0]).publicKey.export({ format: 'der', type: 'spki' }),
      protection: 'software',
      userPresence: o.requireUserPresence && (this.options.presence ?? true),
    };
    this.keys.set(o.keyId, { info, privateKey: file.privateKey });
    return { chain: [...file.chain], algorithm: 'RS256', keyBits: 2048, key: { ...info } };
  }

  private openPkcs12(data: Buffer, password: string): FakePkcs12 {
    const file = (this.options.pkcs12 ?? []).find((f) => f.data.equals(data));
    if (!file) throw Object.assign(new Error('not PKCS#12'), { code: 'E_BAD_FILE' });
    if (file.password !== password) throw Object.assign(new Error('wrong password'), { code: 'E_BAD_PASSWORD' });
    return file;
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
    const { hardwareUuid = 'TEST-UUID', ...device } = this.options.device ?? {};
    return {
      platform: 'macos',
      osVersion: '15.1.0',
      model: 'MacBook Pro',
      modelIdentifier: 'Mac15,3',
      formFactor: 'laptop',
      hostname: 'Juan’s MacBook Pro',
      // Like the native module: "" when there's no usable hardware uuid.
      hardwareIdHash: hardwareUuid ? createHash('sha256').update(`${salt}${hardwareUuid}`).digest('hex') : '',
      chassisType: null,
      virtual: false,
      ...device,
    };
  }
}
