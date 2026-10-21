// Asks paired apps whether a PDF is a version they issued, and pins each
// app's signing CA for the local trust check.
//
// Both endpoints are public on the server (no token, no cookies):
//
//   POST {origin}/signature/verify/lookup   {"sha256", "signed_revision_sha256"}
//   GET  {origin}/signature/trust/ca.pem
//
// Only paired origins are asked: the agent never takes an address from the
// file. Answers are untrusted text: they are checked field by field here and
// shown as text, never markup.
import type * as pkijs from 'pkijs';

import { LOOKUP_VERDICTS, isRecordVerdict, type LookupDocument, type LookupRecord, type LookupSlot } from '../../shared/verdict';
import type { FetchLike } from '../api';
import type { TrustAnchor } from '../store';
import { parsePemCertificates } from './pdfSignature';

export const LOOKUP_PATH = '/signature/verify/lookup';
export const CA_PATH = '/signature/trust/ca.pem';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_LOOKUP_RESPONSE = 256 * 1024;
const MAX_CA_RESPONSE = 64 * 1024;
const MAX_SLOTS = 100;
const MAX_TEXT = 300;
const HEX64 = /^[0-9a-f]{64}$/;

export interface Fingerprints {
  sha256: string;
  /** null: the file has no signature. */
  signedRevisionSha256: string | null;
}

export interface LookupAnswer {
  origin: string;
  record: LookupRecord;
}

/**
 * Why nobody answered:
 *   unsupported  every app said it has no such endpoint (404 / 405 / 501): it
 *                runs a release without PDF verification. Retrying won't help.
 *   unavailable  anything else: offline, a timeout, a server error, a bad answer.
 */
export type LookupFailure = 'unsupported' | 'unavailable';

type OneResult = { record: LookupRecord } | { failure: LookupFailure };

const UNSUPPORTED_STATUSES = new Set([404, 405, 501]);

/**
 * Asks every paired origin at once. The first answer, in pairing order, that
 * recognises the file wins. If they all say not_issued, the first of those is
 * the answer. null when no one answered (offline, 404 with verification
 * switched off, a bad response): "couldn't check", never "not issued".
 */
export async function lookupRecord(
  origins: string[],
  fingerprints: Fingerprints,
  fetch: FetchLike,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<LookupAnswer | null> {
  return (await lookupRecordWithReason(origins, fingerprints, fetch, timeoutMs)).answer;
}

/** lookupRecord(), plus why it came back empty, so the view can say the right thing. */
export async function lookupRecordWithReason(
  origins: string[],
  fingerprints: Fingerprints,
  fetch: FetchLike,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<{ answer: LookupAnswer | null; failure: LookupFailure | null }> {
  const results = await Promise.all(origins.map((origin) => askOneDetailed(origin, fingerprints, fetch, timeoutMs)));
  const answered = results.flatMap((result, i) => ('record' in result ? [{ origin: origins[i], record: result.record }] : []));
  const answer = answered.find((a) => a.record.verdict !== 'not_issued') ?? answered[0] ?? null;

  if (answer) return { answer, failure: null };

  const unsupported = results.length > 0 && results.every((r) => 'failure' in r && r.failure === 'unsupported');
  return { answer: null, failure: unsupported ? 'unsupported' : 'unavailable' };
}

/** One origin's answer, or null for anything but a well-formed 200. */
export async function askOne(origin: string, fingerprints: Fingerprints, fetch: FetchLike, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<LookupRecord | null> {
  const result = await askOneDetailed(origin, fingerprints, fetch, timeoutMs);
  return 'record' in result ? result.record : null;
}

async function askOneDetailed(origin: string, fingerprints: Fingerprints, fetch: FetchLike, timeoutMs: number): Promise<OneResult> {
  const sha256 = fingerprints.sha256.toLowerCase();
  const revision = fingerprints.signedRevisionSha256?.toLowerCase() ?? null;
  if (!HEX64.test(sha256) || (revision !== null && !HEX64.test(revision))) return { failure: 'unavailable' };
  try {
    const response = await fetch(`${origin}${LOOKUP_PATH}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      // Only when the file was saved again after signing; otherwise it's the same hash.
      body: JSON.stringify({ sha256, signed_revision_sha256: revision !== null && revision !== sha256 ? revision : null }),
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (UNSUPPORTED_STATUSES.has(response.status)) return { failure: 'unsupported' };
    if (response.status !== 200) return { failure: 'unavailable' };
    const text = await readCapped(response, MAX_LOOKUP_RESPONSE);
    const record = text === null ? null : parseLookupResponse(JSON.parse(text));
    return record ? { record } : { failure: 'unavailable' };
  } catch {
    return { failure: 'unavailable' };
  }
}

/** The answer's shape, checked; anything off makes the whole answer null. */
export function parseLookupResponse(data: unknown): LookupRecord | null {
  if (!isObject(data)) return null;
  const verdict = data.verdict;
  if (typeof verdict !== 'string' || !(LOOKUP_VERDICTS as readonly string[]).includes(verdict)) return null;
  const issuer = text(data.issuer);
  if (!issuer) return null;

  let document: LookupDocument | null = null;
  if (data.document !== null && data.document !== undefined) {
    document = parseDocument(data.document);
    if (!document) return null;
  }
  // A recognised file always comes with its document (in_progress quotes its counts).
  if (isRecordVerdict(verdict) && !document) return null;

  const rawSlots = data.slots ?? [];
  if (!Array.isArray(rawSlots) || rawSlots.length > MAX_SLOTS) return null;
  const slots: LookupSlot[] = [];
  for (const raw of rawSlots) {
    const slot = parseSlot(raw);
    if (!slot) return null;
    slots.push(slot);
  }

  return { verdict: verdict as LookupRecord['verdict'], issuer, document, slots };
}

function parseDocument(raw: unknown): LookupDocument | null {
  if (!isObject(raw)) return null;
  const counts = [raw.version, raw.versions, raw.signed, raw.required];
  if (!counts.every((n) => Number.isSafeInteger(n) && (n as number) >= 0)) return null;
  const status = text(raw.status);
  if (status === null) return null;
  return {
    title: raw.title === null || raw.title === undefined ? null : text(raw.title),
    version: raw.version as number,
    versions: raw.versions as number,
    signed: raw.signed as number,
    required: raw.required as number,
    status,
  };
}

const SLOT_STATES = ['signed', 'signed_later', 'declined', 'pending'] as const;
const CERTIFICATE_STATES = ['valid', 'revoked', 'unknown', 'unchecked'] as const;

function parseSlot(raw: unknown): LookupSlot | null {
  if (!isObject(raw)) return null;
  const state = raw.state;
  if (typeof state !== 'string' || !(SLOT_STATES as readonly string[]).includes(state)) return null;
  const certificate = raw.certificate ?? null;
  if (certificate !== null && (typeof certificate !== 'string' || !(CERTIFICATE_STATES as readonly string[]).includes(certificate))) return null;
  const signedAt = raw.signed_at ?? null;
  return {
    slot: text(raw.slot) ?? '',
    label: text(raw.label) ?? '',
    state: state as LookupSlot['state'],
    signer: raw.signer === null || raw.signer === undefined ? null : text(raw.signer),
    signed_at: typeof signedAt === 'string' && !Number.isNaN(Date.parse(signedAt)) ? signedAt : null,
    certificate: certificate as LookupSlot['certificate'],
  };
}

// ── CA pinning ──

/** Where pins live: the agent's Store. */
export interface TrustAnchorStore {
  trustAnchor(origin: string): TrustAnchor | null;
  pinTrustAnchor(origin: string, pem: string): Promise<TrustAnchor | null>;
}

/**
 * Each paired origin's CA, fetched once and then always read from the store.
 * A PDF never supplies a trusted root: these are the only anchors the chain
 * check gets. An origin whose CA can't be had yields [], which the check
 * reports as "not checked", not "untrusted".
 */
export class TrustAnchors {
  private readonly inFlight = new Map<string, Promise<pkijs.Certificate[]>>();

  constructor(
    private readonly store: TrustAnchorStore,
    private readonly fetch: FetchLike,
    private readonly timeoutMs = DEFAULT_TIMEOUT_MS,
  ) {}

  async certificates(origin: string): Promise<pkijs.Certificate[]> {
    const pinned = this.store.trustAnchor(origin);
    if (pinned) return safeParse(pinned.pem);
    const running = this.inFlight.get(origin);
    if (running) return running;
    const task = this.fetchAndPin(origin).finally(() => this.inFlight.delete(origin));
    this.inFlight.set(origin, task);
    return task;
  }

  private async fetchAndPin(origin: string): Promise<pkijs.Certificate[]> {
    const pem = await fetchCaPem(origin, this.fetch, this.timeoutMs);
    if (pem === null) return [];
    const anchor = await this.store.pinTrustAnchor(origin, pem).catch(() => null);
    // Unpaired meanwhile: not stored, so don't trust it either.
    return anchor ? safeParse(anchor.pem) : [];
  }
}

/** The CA as PEM, only if it parses as at least one certificate. */
export async function fetchCaPem(origin: string, fetch: FetchLike, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string | null> {
  try {
    const response = await fetch(`${origin}${CA_PATH}`, {
      method: 'GET',
      headers: { Accept: 'application/x-pem-file, text/plain' },
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.status !== 200) return null;
    const pem = await readCapped(response, MAX_CA_RESPONSE);
    if (pem === null || safeParse(pem).length === 0) return null;
    return pem;
  } catch {
    return null;
  }
}

function safeParse(pem: string): pkijs.Certificate[] {
  try {
    return parsePemCertificates(pem);
  } catch {
    return [];
  }
}

// ── Helpers ──

async function readCapped(response: Response, max: number): Promise<string | null> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) return null;
  const body = await response.arrayBuffer();
  if (body.byteLength > max) return null;
  return new TextDecoder().decode(body);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A trimmed, length-capped string, or null for anything else. */
function text(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return clean ? clean.slice(0, MAX_TEXT) : null;
}
