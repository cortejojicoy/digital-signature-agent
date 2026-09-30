// Typed wrapper around native/keystore.node (desktop-agent-plan.md §4.2).
// JS holds key ids and receives public keys and signatures, never key material.
import path from 'node:path';

export type Protection = 'secure_enclave' | 'tpm' | 'software';
export type Algorithm = 'ES256' | 'RS256';

export interface KeyInfo {
  keyId: string;
  algorithm: Algorithm;
  /** SubjectPublicKeyInfo DER. */
  spki: Buffer;
  protection: Protection;
  /** OS-enforced Touch ID / Windows Hello / password on every use. */
  userPresence: boolean;
}

export interface Capabilities {
  hardware: boolean;
  userPresence: boolean;
  attestation: boolean;
}

export interface AttestationResult {
  format: string;
  statement: Buffer;
  chain: Buffer[];
}

export interface DeviceInfo {
  platform: 'macos' | 'windows';
  osVersion: string;
  model: string;
  modelIdentifier: string;
  formFactor: 'laptop' | 'desktop' | 'unknown';
  hostname: string;
  /** sha256(serverSalt || hardware uuid), never the raw uuid (§10.4). */
  hardwareIdHash: string;
}

export interface KeyStore {
  capabilities(): Promise<Capabilities>;
  createKey(o: { keyId: string; requireUserPresence: boolean; biometryOnly?: boolean }): Promise<KeyInfo>;
  findKey(keyId: string): Promise<KeyInfo | null>;
  /** Signs `message` (the addon hashes it). ES256 → DER, RS256 → PKCS#1 v1.5. */
  sign(keyId: string, message: Buffer, reason: string, parentWindow?: Buffer): Promise<Buffer>;
  attest(keyId: string): Promise<AttestationResult | null>;
  deleteKey(keyId: string): Promise<void>;
  deviceInfo(salt: string): Promise<DeviceInfo>;
}

/** Error codes set on `err.code` by the native module. */
export type KeyStoreErrorCode = 'E_NOT_FOUND' | 'E_EXISTS' | 'E_CANCELLED' | 'E_UNSUPPORTED' | 'E_INTERNAL';

export function isKeyStoreError(err: unknown, code: KeyStoreErrorCode): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === code;
}

/** Seals small secrets to this machine's security chip (macOS Secure Enclave). */
export interface Sealer {
  sealingAvailable(): boolean;
  sealData(plain: Buffer): Buffer;
  openData(sealed: Buffer): Buffer;
}

export interface NativeModule extends KeyStore, Sealer {
  configure(o: { keyDirectory: string }): void;
}

/**
 * Loads the addon. Packaged builds keep it in app.asar.unpacked, because
 * native modules can't be loaded from inside an asar archive.
 *
 * `keyDirectory` holds file-backed keys: on macOS, Secure Enclave keys created
 * without the keychain (free builds) are stored there as SE-wrapped blobs
 * that only this Mac's Secure Enclave can use.
 */
export function loadNativeKeyStore(appRoot: string, options: { keyDirectory: string }): NativeModule {
  const file = path
    .join(appRoot, 'native', 'build', 'Release', 'keystore.node')
    .replace(`${path.sep}app.asar${path.sep}`, `${path.sep}app.asar.unpacked${path.sep}`);
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const native = require(file) as NativeModule;
  native.configure({ keyDirectory: options.keyDirectory });
  return native;
}
