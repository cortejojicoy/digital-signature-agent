// Imported PKCS#12 certificates (pkcs12-key-storage-plan.md §6.2, §6.6).
//
// certificates.json holds public data only: the certificate chain and what
// the UI shows. The private key is in the native key store under `keyId`
// (sealed to the Secure Enclave, or in the TPM / Windows key storage) and
// never reaches JS.
//
// The newest certificate is the active one: new certificate pairings use it.
// An older one stays only while a pairing still uses it (§6.6).
import { X509Certificate, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { Algorithm, Protection } from './keystore';
import { PNPKI_ROOTS } from './pnpki';
import { readJson, writeJsonAtomic } from './store';

export interface StoredCertificate {
  id: string;
  keyId: string;
  subject: string;
  commonName: string;
  organization: string;
  issuer: string;
  issuerName: string;
  serialHex: string;
  notBefore: string;
  notAfter: string;
  fingerprint256: string;
  /** Base64 DER, leaf first. */
  chain: string[];
  algorithm: Algorithm;
  protection: Protection;
  userPresence: boolean;
  /** Ends at a known Philippine PKI root. */
  pnpki: boolean;
  importedAt: string;
  /** Wrong passwords in a row (certificate-password-pairing-plan.md §4.3). */
  failedAttempts?: number;
  /** ISO time before which the password isn't tried again. */
  lockedUntil?: string;
}

export type CertificateWarningCode = 'expires_soon' | 'incomplete_chain' | 'not_pnpki';

export interface CertificateWarning {
  code: CertificateWarningCode;
  message: string;
}

/** What the preview shows, from public data only. */
export interface CertificateDescription {
  subject: string;
  commonName: string;
  organization: string;
  issuer: string;
  issuerName: string;
  serialHex: string;
  notBefore: string;
  notAfter: string;
  fingerprint256: string;
  /** Leaf first, then each issuer; certificates unrelated to the leaf are dropped. */
  chain: Buffer[];
  pnpki: boolean;
  warnings: CertificateWarning[];
}

export type CertificateErrorCode =
  // The certificate can't sign, whatever the server says (describeChain).
  | 'invalid_certificate'
  | 'not_a_signing_certificate'
  | 'expired'
  | 'not_yet_valid'
  // From the native key store (keystore.ts).
  | 'E_BAD_PASSWORD'
  | 'E_BAD_FILE'
  | 'E_UNSUPPORTED'
  | 'E_KEY_MISMATCH'
  | 'E_CANCELLED'
  // Managing imported certificates.
  | 'in_use'
  | 'not_found'
  // Using one: too many wrong passwords, wait until retryAt.
  | 'E_LOCKED';

export class CertificateError extends Error {
  constructor(
    readonly code: CertificateErrorCode,
    message: string,
    /** E_BAD_PASSWORD / E_LOCKED: when the next try is allowed, if it has to wait. */
    readonly retryAt?: string,
  ) {
    super(message);
  }
}

// ── Wrong-password back-off (certificate-password-pairing-plan.md §4.3) ──

const FREE_ATTEMPTS = 5;
const FIRST_LOCK_MS = 30_000;
const MAX_LOCK_MS = 15 * 60_000;

/** After 5 wrong passwords in a row, wait 30 s, doubling to 15 min. */
export function lockAfter(failedAttempts: number, now: number): string | undefined {
  if (failedAttempts < FREE_ATTEMPTS) return undefined;
  const ms = Math.min(FIRST_LOCK_MS * 2 ** (failedAttempts - FREE_ATTEMPTS), MAX_LOCK_MS);
  return new Date(now + ms).toISOString();
}

/** "Try again in 30 seconds" / "in 2 minutes". */
export function waitWords(retryAt: string, now: number): string {
  const seconds = Math.max(1, Math.ceil((Date.parse(retryAt) - now) / 1000));
  if (seconds < 60) return `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
}

/** A native import / inspect failure in the user's words (pkcs12-key-storage-plan.md §7.2). */
export function certificateErrorFrom(err: unknown): unknown {
  if (err instanceof CertificateError) return err;
  const code = (err as { code?: unknown } | null)?.code;
  const detail = err instanceof Error ? err.message : '';
  switch (code) {
    case 'E_BAD_PASSWORD':
      return new CertificateError(code, "That password doesn't open this file.");
    case 'E_BAD_FILE':
      return new CertificateError(code, "This isn't a certificate file with a private key (.p12 or .pfx).");
    case 'E_KEY_MISMATCH':
      return new CertificateError(code, "The private key in this file doesn't belong to its certificate.");
    case 'E_UNSUPPORTED':
      return new CertificateError(code, detail ? `${detail[0].toUpperCase()}${detail.slice(1)}.` : "This certificate isn't supported.");
    case 'E_CANCELLED':
      return new CertificateError(code, 'The import was cancelled.');
    default:
      return err;
  }
}

const DAY_MS = 86_400_000;
const EXPIRY_WARNING_DAYS = 30;

/**
 * Orders and checks a chain for the import preview (§6.2). Throws
 * CertificateError for a certificate that can't sign; everything else is a
 * warning, because the app's server has the final say (§9).
 */
export function describeChain(
  chain: Buffer[],
  now = Date.now(),
  roots: ReadonlyArray<{ fingerprint256: string; pem: string }> = PNPKI_ROOTS,
): CertificateDescription {
  let certs: X509Certificate[];
  try {
    certs = chain.map((der) => new X509Certificate(der));
  } catch {
    throw new CertificateError('invalid_certificate', 'The certificate in this file is damaged or not supported.');
  }
  if (certs.length === 0) throw new CertificateError('invalid_certificate', 'The file has no certificate.');
  const leaf = certs[0];

  if (leaf.ca) {
    throw new CertificateError('not_a_signing_certificate', 'This is a certificate authority, not a personal signing certificate.');
  }
  const usage = keyUsage(leaf.raw);
  if (usage && !usage.digitalSignature && !usage.nonRepudiation) {
    throw new CertificateError('not_a_signing_certificate', "This certificate isn't allowed to sign (its key usage excludes signatures).");
  }
  const notBefore = Date.parse(leaf.validFrom);
  const notAfter = Date.parse(leaf.validTo);
  if (now > notAfter) {
    throw new CertificateError('expired', `This certificate expired on ${formatDate(notAfter)}.`);
  }
  if (now < notBefore) {
    throw new CertificateError('not_yet_valid', `This certificate is only valid from ${formatDate(notBefore)}.`);
  }

  const ordered = orderChain(certs);
  const last = ordered[ordered.length - 1];
  const trusted = roots.map((r) => new X509Certificate(r.pem));
  const pnpki = trusted.some(
    (root) =>
      root.fingerprint256 === last.fingerprint256 || (last.checkIssued(root) && safeVerify(last, root)),
  );

  const warnings: CertificateWarning[] = [];
  const daysLeft = Math.floor((notAfter - now) / DAY_MS);
  if (daysLeft < EXPIRY_WARNING_DAYS) {
    warnings.push({
      code: 'expires_soon',
      message: `This certificate expires in ${daysLeft} ${daysLeft === 1 ? 'day' : 'days'}. Renew it soon.`,
    });
  }
  const selfSigned = last.checkIssued(last) && safeVerify(last, last);
  if (!selfSigned && !pnpki) {
    warnings.push({ code: 'incomplete_chain', message: "The file doesn't include the whole issuer chain; the app may refuse it." });
  }
  if (!pnpki) {
    warnings.push({ code: 'not_pnpki', message: 'This certificate is not issued under the Philippine PKI (PNPKI).' });
  }

  const subject = parseName(leaf.subject);
  const issuer = parseName(leaf.issuer);
  return {
    subject: oneLine(leaf.subject),
    commonName: subject.CN ?? oneLine(leaf.subject),
    organization: subject.O ?? '',
    issuer: oneLine(leaf.issuer),
    issuerName: issuer.CN ?? oneLine(leaf.issuer),
    serialHex: leaf.serialNumber.toUpperCase(),
    notBefore: new Date(notBefore).toISOString(),
    notAfter: new Date(notAfter).toISOString(),
    fingerprint256: leaf.fingerprint256,
    chain: ordered.map((c) => c.raw),
    pnpki,
    warnings,
  };
}

/** Leaf, then whichever certificate issued and signed the previous one. */
function orderChain(certs: X509Certificate[]): X509Certificate[] {
  const ordered = [certs[0]];
  const rest = certs.slice(1);
  for (;;) {
    const current = ordered[ordered.length - 1];
    if (current.checkIssued(current)) break; // self-signed: the top
    const index = rest.findIndex((c) => current.checkIssued(c) && safeVerify(current, c));
    if (index < 0) break;
    ordered.push(rest.splice(index, 1)[0]);
  }
  return ordered;
}

function safeVerify(cert: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return cert.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

/** "CN=Test UP 4\nO=…" → { CN: 'Test UP 4', O: '…' }. The first value of each key wins. */
function parseName(name: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of name.split('\n')) {
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq);
    out[key] ??= line.slice(eq + 1);
  }
  return out;
}

function oneLine(name: string): string {
  return name.split('\n').join(', ');
}

function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString('en-PH', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
}

// ── Key Usage (RFC 5280 §4.2.1.3) ──
//
// node:crypto's X509Certificate exposes extended key usage but not the basic
// key usage bits, so this reads the one extension from the DER.

interface Tlv {
  tag: number;
  start: number; // first content byte
  end: number; // one past the last content byte
}

function readTlv(der: Buffer, offset: number): Tlv {
  if (offset + 2 > der.length) throw new Error('truncated DER');
  const tag = der[offset];
  let length = der[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 4 || start + bytes > der.length) throw new Error('bad DER length');
    length = 0;
    for (let i = 0; i < bytes; i++) length = length * 256 + der[start + i];
    start += bytes;
  }
  const end = start + length;
  if (end > der.length) throw new Error('truncated DER');
  return { tag, start, end };
}

function children(der: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let offset = parent.start; offset < parent.end; ) {
    const child = readTlv(der, offset);
    out.push(child);
    offset = child.end;
  }
  return out;
}

const KEY_USAGE_OID = Buffer.from([0x55, 0x1d, 0x0f]); // 2.5.29.15

/** null when the certificate has no key usage extension (any use allowed). */
export function keyUsage(der: Buffer): { digitalSignature: boolean; nonRepudiation: boolean } | null {
  try {
    const certificate = readTlv(der, 0);
    const tbs = children(der, certificate)[0];
    // Extensions are the [3] EXPLICIT field of TBSCertificate.
    const wrapper = children(der, tbs).find((t) => t.tag === 0xa3);
    if (!wrapper) return null;
    const extensions = children(der, wrapper)[0];
    for (const extension of children(der, extensions)) {
      const [oid, ...rest] = children(der, extension);
      if (oid.tag !== 0x06 || !der.subarray(oid.start, oid.end).equals(KEY_USAGE_OID)) continue;
      const value = rest[rest.length - 1]; // after the optional `critical` BOOLEAN
      const bits = readTlv(der, value.start); // BIT STRING inside the OCTET STRING
      if (bits.tag !== 0x03 || bits.end - bits.start < 2) return { digitalSignature: false, nonRepudiation: false };
      const first = der[bits.start + 1]; // after the unused-bits byte; bit 0 is the MSB
      return { digitalSignature: (first & 0x80) !== 0, nonRepudiation: (first & 0x40) !== 0 };
    }
    return null;
  } catch {
    return null;
  }
}

// ── Storage ──

interface CertificatesFile {
  version: 1;
  certificates: StoredCertificate[];
}

export class CertificateStore {
  private certificates: StoredCertificate[] = [];

  constructor(private readonly dir: string) {}

  async load(): Promise<void> {
    const saved = await readJson<CertificatesFile>(this.file());
    this.certificates = saved?.version === 1 && Array.isArray(saved.certificates) ? saved.certificates : [];
  }

  /** Oldest first. */
  list(): StoredCertificate[] {
    return this.certificates.map((c) => ({ ...c, chain: [...c.chain] }));
  }

  get(id: string): StoredCertificate | null {
    const found = this.certificates.find((c) => c.id === id);
    return found ? { ...found, chain: [...found.chain] } : null;
  }

  /** The newest certificate: the one new certificate pairings use. */
  active(): StoredCertificate | null {
    const last = this.certificates[this.certificates.length - 1];
    return last ? this.get(last.id) : null;
  }

  findByFingerprint(fingerprint256: string): StoredCertificate | null {
    const found = this.certificates.find((c) => c.fingerprint256 === fingerprint256);
    return found ? this.get(found.id) : null;
  }

  async save(certificate: StoredCertificate): Promise<void> {
    this.certificates = [...this.certificates.filter((c) => c.id !== certificate.id), { ...certificate }];
    await this.flush();
  }

  async remove(id: string): Promise<void> {
    this.certificates = this.certificates.filter((c) => c.id !== id);
    await this.flush();
  }

  /** Records a password attempt; returns the certificate as stored now. */
  async recordPassword(id: string, correct: boolean, now = Date.now()): Promise<StoredCertificate | null> {
    const found = this.certificates.find((c) => c.id === id);
    if (!found) return null;
    if (correct) {
      if (!found.failedAttempts && !found.lockedUntil) return this.get(id);
      delete found.failedAttempts;
      delete found.lockedUntil;
    } else {
      found.failedAttempts = (found.failedAttempts ?? 0) + 1;
      found.lockedUntil = lockAfter(found.failedAttempts, now);
    }
    await this.flush();
    return this.get(id);
  }

  private async flush(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    await writeJsonAtomic(this.file(), { version: 1, certificates: this.certificates } satisfies CertificatesFile);
  }

  private file(): string {
    return path.join(this.dir, 'certificates.json');
  }
}

/** A fresh id and the key id its private key is imported under. */
export function newCertificateIds(): { id: string; keyId: string } {
  const id = randomBytes(8).toString('hex');
  return { id, keyId: `ds.cert.${id}.identity` };
}
