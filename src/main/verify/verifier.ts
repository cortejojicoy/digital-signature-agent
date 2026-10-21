// "Verify a PDF": read the file, check its last signature here, ask the
// paired apps about it, and combine the two (shared/verdict.ts).
//
// The PDF is untrusted input. It is read once, in the main process, capped
// in size and checked for the %PDF- header; nothing in it is rendered,
// executed or followed. The renderer gets the verdict, never the bytes.
import { webcrypto } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import * as pkijs from 'pkijs';

import { combineVerdict, type Inspection, type LookupRecord, type Verdict } from '../../shared/verdict';
import type { FetchLike } from '../api';
import { lookupRecordWithReason, TrustAnchors, type LookupFailure, type TrustAnchorStore } from './lookup';
import { findSignatures, inspectPdf, signedBytes, verifyCms } from './pdfSignature';

export const MAX_PDF_BYTES = 50 * 1024 * 1024;
const PDF_HEADER = Buffer.from('%PDF-', 'latin1');

export type PdfFileErrorCode = 'not_found' | 'not_a_file' | 'empty' | 'too_large' | 'not_pdf' | 'unreadable';

export class PdfFileError extends Error {
  constructor(
    readonly code: PdfFileErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'PdfFileError';
  }
}

export interface PdfFile {
  name: string;
  size: number;
  bytes: Uint8Array;
}

/**
 * Reads a PDF the user chose, dropped or opened with the agent. The handle is
 * opened once and checked through it, so the file can't be swapped between
 * the size check and the read.
 */
export async function readPdfFile(filePath: string, maxBytes = MAX_PDF_BYTES): Promise<PdfFile> {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || filePath.includes('\0')) {
    throw new PdfFileError('not_found', "That file can't be found.");
  }
  const name = path.basename(filePath);
  let handle: fs.FileHandle;
  try {
    handle = await fs.open(filePath, 'r');
  } catch {
    throw new PdfFileError('not_found', "That file can't be opened.");
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new PdfFileError('not_a_file', "That isn't a file.");
    if (stat.size === 0) throw new PdfFileError('empty', 'That file is empty.');
    if (stat.size > maxBytes) {
      throw new PdfFileError('too_large', `That file is larger than ${Math.round(maxBytes / (1024 * 1024))} MB.`);
    }
    const bytes = new Uint8Array(stat.size);
    let read = 0;
    while (read < bytes.length) {
      const { bytesRead } = await handle.read(bytes, read, bytes.length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    if (read !== stat.size) throw new PdfFileError('unreadable', "That file couldn't be read completely.");
    if (!PDF_HEADER.equals(Buffer.from(bytes.buffer, bytes.byteOffset, Math.min(PDF_HEADER.length, bytes.length)))) {
      throw new PdfFileError('not_pdf', "That isn't a PDF file.");
    }
    return { name, size: stat.size, bytes };
  } catch (err) {
    if (err instanceof PdfFileError) throw err;
    throw new PdfFileError('unreadable', "That file couldn't be read.");
  } finally {
    await handle.close().catch(() => {});
  }
}

/** A paired app to ask, in pairing order. */
export interface VerifyTarget {
  origin: string;
  name: string;
}

export interface VerifyReport {
  verdict: Verdict;
  /** false: nothing is paired, so only the local check ran. */
  paired: boolean;
  /** For the wording: the record's issuer, else the first paired app's name. */
  issuer: string;
  /** Whose CA the embedded signature chained to, or was checked against. */
  trustIssuer: string;
  /** The app whose record answered. */
  origin: string | null;
  inspection: Inspection;
  record: LookupRecord | null;
  /** Why record is null when apps were asked: "unsupported" means no app has PDF verification yet. */
  lookupFailure: LookupFailure | null;
}

export interface VerifierOptions {
  /** Paired apps, in pairing order. Read on every check, so it follows (un)pairing. */
  targets: () => VerifyTarget[];
  anchors: TrustAnchorStore;
  fetch: FetchLike;
  timeoutMs?: number;
}

const FALLBACK_ISSUER = 'the issuing app';

let engineReady = false;

/** PKI.js finds globalThis.crypto by itself on Node 22+; set it anyway, so it never depends on load order. */
function ensureCryptoEngine(): void {
  if (engineReady) return;
  pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto }));
  engineReady = true;
}

export class PdfVerifier {
  private readonly anchors: TrustAnchors;

  constructor(private readonly options: VerifierOptions) {
    this.anchors = new TrustAnchors(options.anchors, options.fetch, options.timeoutMs);
  }

  async verify(bytes: Uint8Array): Promise<VerifyReport> {
    ensureCryptoEngine();
    // Fingerprints and "is it intact" first; trust needs to know whom to ask.
    const local = await inspectPdf(bytes, []);
    const targets = uniqueOrigins(this.options.targets());

    if (targets.length === 0) {
      return {
        verdict: combineVerdict(local, null),
        paired: false,
        issuer: FALLBACK_ISSUER,
        trustIssuer: FALLBACK_ISSUER,
        origin: null,
        inspection: local,
        record: null,
        lookupFailure: null,
      };
    }

    const { answer, failure } = await lookupRecordWithReason(
      targets.map((t) => t.origin),
      { sha256: local.sha256, signedRevisionSha256: local.signedRevisionSha256 },
      this.options.fetch,
      this.options.timeoutMs,
    );
    const nameOf = (origin: string) =>
      answer && answer.origin === origin ? answer.record.issuer : (targets.find((t) => t.origin === origin)?.name ?? FALLBACK_ISSUER);
    const issuer = answer ? answer.record.issuer : targets[0].name;

    // The app that answered first, then the others: the first CA it chains to wins.
    const order = answer ? [answer.origin, ...targets.map((t) => t.origin).filter((o) => o !== answer.origin)] : targets.map((t) => t.origin);
    const trust = await this.checkTrust(bytes, local, order);
    const signatures = local.signatures.map((signature, i) =>
      trust[i] ? { ...signature, trusted: trust[i].trusted, error: trust[i].error } : signature,
    );
    const inspection: Inspection = { ...local, signatures, signature: signatures.length > 0 ? signatures[signatures.length - 1] : null };
    const lastTrust = trust.length > 0 ? trust[trust.length - 1] : null;

    return {
      verdict: combineVerdict(inspection, answer?.record ?? null),
      paired: true,
      issuer,
      trustIssuer: lastTrust?.origin ? nameOf(lastTrust.origin) : issuer,
      origin: answer?.origin ?? null,
      inspection,
      record: answer?.record ?? null,
      lookupFailure: answer ? null : failure,
    };
  }

  /**
   * Each embedded signature's chain against each pinned CA in turn, in file
   * order. An entry is null when there's nothing to check (that signature
   * isn't intact) or no CA could be had.
   */
  private async checkTrust(
    bytes: Uint8Array,
    local: Inspection,
    origins: string[],
  ): Promise<Array<{ trusted: boolean; error: string | null; origin: string } | null>> {
    const found = findSignatures(bytes);
    const results: Array<{ trusted: boolean; error: string | null; origin: string } | null> = [];

    for (const [i, entry] of found.entries()) {
      if (!local.signatures[i]?.intact) {
        results.push(null);
        continue;
      }
      const data = signedBytes(bytes, entry.byteRange);
      let result: { trusted: boolean; error: string | null; origin: string } | null = null;
      for (const origin of origins) {
        const certificates = await this.anchors.certificates(origin);
        if (certificates.length === 0) continue;
        const check = await verifyCms(entry.contents, data, certificates);
        if (check.trusted === true) {
          result = { trusted: true, error: null, origin };
          break;
        }
        result ??= { trusted: false, error: check.error, origin };
      }
      results.push(result);
    }

    return results;
  }
}

function uniqueOrigins(targets: VerifyTarget[]): VerifyTarget[] {
  const seen = new Set<string>();
  return targets.filter((t) => !seen.has(t.origin) && seen.add(t.origin));
}
