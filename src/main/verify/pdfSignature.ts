// Read and check the last digital signature in a PDF, on this computer.
//
// Mirrors resources/js/verify/pdfSignature.js in kukux/digital-signature, which
// the web verify page runs in the browser. Keep the two in step: both must
// fingerprint a file the same way, or the lookup stops finding anything.
//
// The agent fingerprints a file and asks the server whether it is a version
// the system issued. That answer is only as good as the fingerprint, so this
// module does the parts that need the file itself:
//
//   - sha256 of the whole file, the lookup key;
//   - the signed revision: the bytes up to the end of the last signature's
//     /ByteRange. A file that was edited and saved after signing (an
//     incremental update) still starts with exactly the bytes that were
//     signed, so hashing this prefix finds the version the signer signed
//     even though the whole-file hash no longer matches anything;
//   - the PKCS#7 itself: does it cover these bytes, and does its certificate
//     chain end at the CA this system trusts.
//
// Progressive signing (FPDI rebuilds the file on every pass) leaves one
// signature per file, the last signer's. Earlier signatories are proven by
// the record, not by this module, which is why the agent always asks both.
//
// The file is untrusted: nothing here renders it or follows anything in it.
// It is read as bytes, a regex finds /ByteRange, and PKI.js parses the one
// DER blob it points at. Pure: no filesystem and no network
// (test/pdfSignature.test.ts).
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import type { EmbeddedSignature, Inspection } from '../../shared/verdict';

const BYTE_RANGE = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;

/** OID of the CMS signingTime signed attribute. */
const SIGNING_TIME = '1.2.840.113549.1.9.5';

/** OID of the X.520 commonName attribute. */
const COMMON_NAME = '2.5.4.3';

export type ByteRange = [number, number, number, number];

export interface FoundSignature {
  byteRange: ByteRange;
  revisionEnd: number;
  contents: Uint8Array;
  coversWholeFile: boolean;
}

export type CmsCheck = Omit<EmbeddedSignature, 'coversWholeFile'>;

/**
 * Latin-1 view of the bytes: one char per byte, so string offsets are byte
 * offsets. Built in chunks; String.fromCharCode(...bytes) overflows the call
 * stack on a multi-megabyte file.
 */
function latin1(bytes: Uint8Array): string {
  let out = '';
  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk) as unknown as number[]);
  }

  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length >> 1);

  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }

  return out;
}

/** An ArrayBuffer holding exactly these bytes, for the APIs that want one. */
function exactBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer instanceof ArrayBuffer && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? bytes.buffer
    : bytes.slice().buffer;
}

export function toHex(buffer: ArrayBuffer | Uint8Array): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(bytes: Uint8Array, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<string> {
  return toHex(await subtle.digest('SHA-256', exactBuffer(bytes)));
}

/**
 * Every signature in the file, in the order they were added.
 *
 * Ranges that don't make sense for this file (outside it, overlapping, a gap
 * that isn't a hex string) are skipped, so a /ByteRange that merely appears
 * inside some text can't be mistaken for a signature. Order is by where each
 * signed revision ends: an incremental update appends, so a later signature
 * covers more of the file.
 *
 * Progressive signing (the package's default) leaves one: each pass rebuilds
 * the file and drops the earlier PKCS#7 blocks. A PDF signed incrementally
 * keeps all of them, and then each can be checked here.
 */
export function findSignatures(bytes: Uint8Array): FoundSignature[] {
  const text = latin1(bytes);
  const found = new Map<number, FoundSignature>();

  for (const match of text.matchAll(BYTE_RANGE)) {
    const [a, b, c, d] = match.slice(1, 5).map(Number);

    if (a !== 0 || b <= 0 || c <= b || d < 0 || c + d > bytes.length) {
      continue;
    }

    const gap = text.slice(b, c);

    if (!/^<[0-9a-fA-F\s]*>$/.test(gap)) {
      continue;
    }

    // The same dictionary can be written twice (an object stream and its
    // xref twin); one signature per revision end.
    found.set(c + d, {
      byteRange: [a, b, c, d],
      revisionEnd: c + d,
      contents: hexToBytes(gap.slice(1, -1)),
      coversWholeFile: c + d === bytes.length,
    });
  }

  return [...found.values()].sort((x, y) => x.revisionEnd - y.revisionEnd);
}

/**
 * The last signature: the one that covers the most of the file, and so the
 * one the file's integrity rests on. null when there is none.
 */
export function findLastSignature(bytes: Uint8Array): FoundSignature | null {
  return findSignatures(bytes).at(-1) ?? null;
}

/** The bytes a signature's /ByteRange covers, joined: what was actually signed. */
export function signedBytes(bytes: Uint8Array, byteRange: ByteRange): Uint8Array {
  const [a, b, c, d] = byteRange;
  const out = new Uint8Array(b + d);

  out.set(bytes.subarray(a, a + b), 0);
  out.set(bytes.subarray(c, c + d), b);

  return out;
}

export function parsePemCertificates(pem: string): pkijs.Certificate[] {
  const blocks = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];

  return blocks.map((block) => {
    const b64 = block.replace(/-----[A-Z ]+-----|\s+/g, '');
    const der = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));

    return pkijs.Certificate.fromBER(der);
  });
}

function commonName(certificate: pkijs.CertificateSetItem | null | undefined): string | null {
  if (!(certificate instanceof pkijs.Certificate)) return null;
  const cn = certificate.subject?.typesAndValues?.find((tv) => tv.type === COMMON_NAME);

  return cn ? String((cn.value as { valueBlock: { value: unknown } }).valueBlock.value) : null;
}

function signingTime(signerInfo: pkijs.SignerInfo | undefined): string | null {
  const attribute = signerInfo?.signedAttrs?.attributes?.find((a) => a.type === SIGNING_TIME);
  const value = attribute?.values?.[0] as { toDate?: () => Date } | undefined;

  return value?.toDate ? value.toDate().toISOString() : null;
}

/**
 * Check one PKCS#7 / CMS blob against the bytes it should cover.
 *
 * intact:  the signature verifies and its messageDigest is these bytes' hash.
 * trusted: the signer's chain ends at one of trustedCerts. null when no
 *          trusted CA was given (the agent couldn't fetch one): "not checked",
 *          which is not the same as "untrusted".
 */
export async function verifyCms(cmsDer: Uint8Array, data: Uint8Array, trustedCerts: pkijs.Certificate[] = []): Promise<CmsCheck> {
  let signedData: pkijs.SignedData;

  try {
    // The /Contents placeholder is zero-padded past the end of the DER,
    // so read the first element and ignore what follows.
    const asn = asn1js.fromBER(exactBuffer(cmsDer));

    if (asn.offset === -1) {
      throw new Error('not DER');
    }

    const info = new pkijs.ContentInfo({ schema: asn.result });
    signedData = new pkijs.SignedData({ schema: info.content });
  } catch {
    return { intact: false, trusted: null, signer: null, signedAt: null, error: 'unreadable' };
  }

  const signerInfo = signedData.signerInfos?.[0];
  const base = { signedAt: signingTime(signerInfo) };
  const signed = exactBuffer(data);

  // First the maths alone, so a broken signature is reported as broken and
  // not as "untrusted" just because the chain check ran first.
  let intact = false;
  let signerCertificate: pkijs.Certificate | null = null;

  try {
    const result = await signedData.verify({ signer: 0, data: signed, checkChain: false, extendedMode: true });
    intact = result.signatureVerified === true;
    signerCertificate = result.signerCertificate ?? null;
  } catch (error) {
    signerCertificate = (error as { signerCertificate?: pkijs.Certificate | null })?.signerCertificate ?? null;
  }

  const signer = commonName(signerCertificate ?? signedData.certificates?.[0]);

  if (!intact) {
    return { ...base, intact: false, trusted: null, signer, error: 'signature_mismatch' };
  }

  if (trustedCerts.length === 0) {
    return { ...base, intact: true, trusted: null, signer, error: null };
  }

  try {
    const result = await signedData.verify({
      signer: 0,
      data: signed,
      checkChain: true,
      trustedCerts,
      extendedMode: true,
    });

    const trusted = result.signatureVerified === true && result.signerCertificateVerified === true;

    return { ...base, intact: true, trusted, signer, error: trusted ? null : 'untrusted_chain' };
  } catch {
    return { ...base, intact: true, trusted: false, signer, error: 'untrusted_chain' };
  }
}

/**
 * Everything a verifier needs from a file: its fingerprints and what each of
 * its signatures says about itself.
 *
 * `signature` is the last one, which the verdict turns on: it covers every
 * byte before it, so if it is intact nothing earlier was changed after.
 * `signatures` is all of them, oldest first, for the per-signature rows.
 */
export async function inspectPdf(
  bytes: Uint8Array,
  trustedCerts: pkijs.Certificate[] = [],
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Inspection> {
  const sha256 = await sha256Hex(bytes, subtle);
  const found = findSignatures(bytes);

  if (found.length === 0) {
    return { sha256, signedRevisionSha256: null, signature: null, signatures: [] };
  }

  const signatures: EmbeddedSignature[] = [];

  for (const entry of found) {
    const check = await verifyCms(entry.contents, signedBytes(bytes, entry.byteRange), trustedCerts);
    signatures.push({ ...check, coversWholeFile: entry.coversWholeFile });
  }

  const last = found[found.length - 1];
  const signedRevisionSha256 = last.coversWholeFile ? sha256 : await sha256Hex(bytes.subarray(0, last.revisionEnd), subtle);

  return { sha256, signedRevisionSha256, signature: signatures[signatures.length - 1], signatures };
}
