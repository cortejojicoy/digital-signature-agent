// "Verify a PDF": the lookup client, CA pinning and the verifier, against the
// real signed fixtures and a mocked fetch.
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { FetchLike } from '../src/main/api';
import { Store, type PairedServer } from '../src/main/store';
import { askOne, lookupRecord, parseLookupResponse, TrustAnchors } from '../src/main/verify/lookup';
import { PdfVerifier, readPdfFile } from '../src/main/verify/verifier';
import { fakeCipher } from './support/fake-cipher';

const dir = path.join(__dirname, 'fixtures', 'verification');
const read = (name: string) => new Uint8Array(readFileSync(path.join(dir, name)));
const CA = readFileSync(path.join(dir, 'ca.pem'), 'utf8');
const OTHER_CA = readFileSync(path.join(dir, 'other-ca.pem'), 'utf8');
const hashes = JSON.parse(readFileSync(path.join(dir, 'hashes.json'), 'utf8')) as { sha256: Record<string, string> };

const A = 'https://a.example.ph';
const B = 'https://b.example.ph';
const SHA = 'a'.repeat(64);

const document = { title: 'Accomplishment Report', version: 2, versions: 2, signed: 2, required: 2, status: 'completed' };
const slots = [
  { slot: 'prepared', label: 'Prepared by', state: 'signed', signer: 'Ana Prepared', signed_at: '2026-10-01T01:00:00Z', certificate: 'valid' },
  { slot: 'accepted', label: 'Accepted by', state: 'signed', signer: 'Ben Accepted', signed_at: '2026-10-02T01:00:00Z', certificate: 'revoked' },
];
const answer = (verdict: string, issuer = 'UPLB Signature') =>
  verdict === 'not_issued' ? { verdict, issuer, document: null, slots: [] } : { verdict, issuer, document, slots };

type Route = { status?: number; body?: unknown; text?: string } | 'offline';

/** fetch by origin + path; records every call. */
function mockFetch(routes: Record<string, Route>) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    const route = routes[url];
    if (route === undefined) return new Response('not found', { status: 404 });
    if (route === 'offline') throw new TypeError('fetch failed');
    const body = route.text ?? JSON.stringify(route.body ?? {});
    return new Response(body, { status: route.status ?? 200 });
  };
  return { fetch, calls };
}

const lookup = (origin: string) => `${origin}/signature/verify/lookup`;
const caUrl = (origin: string) => `${origin}/signature/trust/ca.pem`;

/** Store-shaped pins in memory, counting writes. */
function memoryAnchors(paired: string[] = [A, B]) {
  const pins = new Map<string, { pem: string; pinnedAt: string }>();
  let writes = 0;
  return {
    pins,
    writes: () => writes,
    trustAnchor: (origin: string) => pins.get(origin) ?? null,
    pinTrustAnchor: async (origin: string, pem: string) => {
      if (pins.has(origin)) return pins.get(origin)!;
      if (!paired.includes(origin)) return null;
      writes++;
      const anchor = { pem, pinnedAt: new Date().toISOString() };
      pins.set(origin, anchor);
      return anchor;
    },
  };
}

describe('lookup client', () => {
  it('posts both fingerprints only when the file was saved after signing, without credentials or redirects', async () => {
    const { fetch, calls } = mockFetch({ [lookup(A)]: { body: answer('complete') } });
    await askOne(A, { sha256: SHA, signedRevisionSha256: SHA }, fetch);
    await askOne(A, { sha256: SHA, signedRevisionSha256: 'b'.repeat(64) }, fetch);
    await askOne(A, { sha256: SHA, signedRevisionSha256: null }, fetch);

    expect(calls.map((c) => c.url)).toEqual([lookup(A), lookup(A), lookup(A)]);
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.credentials).toBe('omit');
    expect(calls[0].init.redirect).toBe('error');
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBeUndefined();
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ sha256: SHA, signed_revision_sha256: null });
    expect(JSON.parse(String(calls[1].init.body))).toEqual({ sha256: SHA, signed_revision_sha256: 'b'.repeat(64) });
    expect(JSON.parse(String(calls[2].init.body))).toEqual({ sha256: SHA, signed_revision_sha256: null });
  });

  it('with several pairings, the first answer that recognises the file wins', async () => {
    const one = mockFetch({ [lookup(A)]: { body: answer('not_issued', 'App A') }, [lookup(B)]: { body: answer('superseded', 'App B') } });
    expect(await lookupRecord([A, B], { sha256: SHA, signedRevisionSha256: null }, one.fetch)).toMatchObject({
      origin: B,
      record: { verdict: 'superseded', issuer: 'App B' },
    });

    const two = mockFetch({ [lookup(A)]: { body: answer('in_progress', 'App A') }, [lookup(B)]: { body: answer('complete', 'App B') } });
    expect(await lookupRecord([A, B], { sha256: SHA, signedRevisionSha256: null }, two.fetch)).toMatchObject({
      origin: A,
      record: { verdict: 'in_progress' },
    });
  });

  it('all not_issued is not_issued, from the first that answered', async () => {
    const { fetch } = mockFetch({ [lookup(A)]: 'offline', [lookup(B)]: { body: answer('not_issued', 'App B') } });
    expect(await lookupRecord([A, B], { sha256: SHA, signedRevisionSha256: null }, fetch)).toMatchObject({
      origin: B,
      record: { verdict: 'not_issued', issuer: 'App B' },
    });
  });

  it('no answer at all is null: offline, verification switched off (404), bad input (422), or a malformed body', async () => {
    const { fetch } = mockFetch({
      [lookup(A)]: 'offline',
      [lookup(B)]: { status: 404, body: { message: 'Not Found' } },
    });
    expect(await lookupRecord([A, B], { sha256: SHA, signedRevisionSha256: null }, fetch)).toBeNull();

    const bad = mockFetch({ [lookup(A)]: { status: 422, body: { message: 'invalid' } }, [lookup(B)]: { text: '<html>' } });
    expect(await lookupRecord([A, B], { sha256: SHA, signedRevisionSha256: null }, bad.fetch)).toBeNull();
  });

  it('never sends something that is not a fingerprint', async () => {
    const { fetch, calls } = mockFetch({ [lookup(A)]: { body: answer('complete') } });
    expect(await askOne(A, { sha256: 'nope', signedRevisionSha256: null }, fetch)).toBeNull();
    expect(calls).toEqual([]);
  });

  it('checks the answer field by field', () => {
    expect(parseLookupResponse(answer('complete'))).toMatchObject({ verdict: 'complete', document: { signed: 2 } });
    expect(parseLookupResponse({ ...answer('complete'), verdict: 'trust_me' })).toBeNull();
    expect(parseLookupResponse({ ...answer('in_progress'), document: null })).toBeNull();
    expect(parseLookupResponse({ ...answer('complete'), issuer: '' })).toBeNull();
    expect(parseLookupResponse({ ...answer('complete'), slots: [{ ...slots[0], state: 'forged' }] })).toBeNull();
    expect(parseLookupResponse({ ...answer('complete'), slots: [{ ...slots[0], certificate: 'great' }] })).toBeNull();
    expect(parseLookupResponse({ ...answer('complete'), document: { ...document, signed: -1 } })).toBeNull();
    expect(parseLookupResponse([])).toBeNull();
    // Text stays text, trimmed and capped.
    const long = parseLookupResponse({ ...answer('complete'), issuer: `  <b>${'x'.repeat(1000)}</b>  ` });
    expect(long?.issuer.startsWith('<b>')).toBe(true);
    expect(long?.issuer.length).toBe(300);
  });
});

describe('CA pinning', () => {
  it('fetches each paired CA once, then reads the stored copy', async () => {
    const anchors = memoryAnchors();
    const { fetch, calls } = mockFetch({ [caUrl(A)]: { text: CA } });
    const trust = new TrustAnchors(anchors, fetch);

    expect(await trust.certificates(A)).toHaveLength(1);
    expect(await trust.certificates(A)).toHaveLength(1);
    await Promise.all([trust.certificates(A), trust.certificates(A)]);

    expect(calls.map((c) => c.url)).toEqual([caUrl(A)]);
    expect(anchors.writes()).toBe(1);
    expect(anchors.pins.get(A)?.pem).toBe(CA);
  });

  it('keeps the pin even if the server later serves another CA', async () => {
    const anchors = memoryAnchors();
    anchors.pins.set(A, { pem: CA, pinnedAt: '2026-10-01T00:00:00Z' });
    const { fetch, calls } = mockFetch({ [caUrl(A)]: { text: OTHER_CA } });
    await new TrustAnchors(anchors, fetch).certificates(A);
    expect(calls).toEqual([]);
    expect(anchors.pins.get(A)?.pem).toBe(CA);
  });

  it('pins nothing it can not parse or fetch, and trusts nothing it did not pin', async () => {
    const anchors = memoryAnchors([A, B]);
    const { fetch } = mockFetch({ [caUrl(A)]: { text: 'not a certificate' }, [caUrl(B)]: { status: 404 }, [caUrl('https://c.example.ph')]: { text: CA } });
    const trust = new TrustAnchors(anchors, fetch);
    expect(await trust.certificates(A)).toEqual([]);
    expect(await trust.certificates(B)).toEqual([]);
    // Fetched but not paired: the store refuses the pin, so it isn't used either.
    expect(await trust.certificates('https://c.example.ph')).toEqual([]);
    expect(anchors.pins.size).toBe(0);
  });
});

describe('PdfVerifier', () => {
  const targets = [
    { origin: A, name: 'App A' },
    { origin: B, name: 'App B' },
  ];

  it('combines the record with the local check, trusting only the pinned CA', async () => {
    const anchors = memoryAnchors();
    const { fetch, calls } = mockFetch({
      [lookup(A)]: { body: answer('not_issued', 'App A') },
      [lookup(B)]: { body: answer('complete', 'UPLB Signature') },
      [caUrl(A)]: { text: OTHER_CA },
      [caUrl(B)]: { text: CA },
    });
    const verifier = new PdfVerifier({ targets: () => targets, anchors, fetch });
    const report = await verifier.verify(read('v2.pdf'));

    expect(report.verdict).toBe('complete');
    expect(report.paired).toBe(true);
    expect(report.origin).toBe(B);
    expect(report.issuer).toBe('UPLB Signature');
    expect(report.trustIssuer).toBe('UPLB Signature');
    expect(report.inspection.sha256).toBe(hashes.sha256['v2.pdf']);
    expect(report.inspection.signature).toMatchObject({ intact: true, trusted: true, signer: 'Ben Accepted' });
    expect(report.record?.slots).toHaveLength(2);
    // Only paired origins were ever asked: the agent takes no address from the file.
    expect(calls.every((c) => c.url.startsWith(`${A}/`) || c.url.startsWith(`${B}/`))).toBe(true);

    // A second file: the CA comes from the pin, not the network.
    const before = calls.filter((c) => c.url.endsWith('ca.pem')).length;
    await verifier.verify(read('v1.pdf'));
    expect(calls.filter((c) => c.url.endsWith('ca.pem')).length).toBe(before);
  });

  it('a file signed under a CA no paired app pinned is intact but untrusted', async () => {
    const anchors = memoryAnchors();
    const { fetch } = mockFetch({
      [lookup(A)]: { body: answer('not_issued', 'App A') },
      [lookup(B)]: { body: answer('not_issued', 'App B') },
      [caUrl(A)]: { text: OTHER_CA },
      [caUrl(B)]: { text: OTHER_CA },
    });
    const report = await new PdfVerifier({ targets: () => targets, anchors, fetch }).verify(read('v2.pdf'));

    expect(report.verdict).toBe('not_issued');
    expect(report.issuer).toBe('App A');
    expect(report.inspection.signature).toMatchObject({ intact: true, trusted: false, error: 'untrusted_chain' });
  });

  it('offline is lookup_failed, never not_issued, and trust is "not checked"', async () => {
    const { fetch } = mockFetch({ [lookup(A)]: 'offline', [lookup(B)]: 'offline', [caUrl(A)]: 'offline', [caUrl(B)]: 'offline' });
    const report = await new PdfVerifier({ targets: () => targets, anchors: memoryAnchors(), fetch }).verify(read('v2.pdf'));

    expect(report.verdict).toBe('lookup_failed');
    expect(report.record).toBeNull();
    expect(report.issuer).toBe('App A');
    expect(report.inspection.signature).toMatchObject({ intact: true, trusted: null });
  });

  it('a broken signature stays broken even when the servers are unreachable', async () => {
    const bytes = read('v2.pdf');
    bytes[200] = bytes[200] === 0x20 ? 0x21 : 0x20;
    const { fetch } = mockFetch({});
    const report = await new PdfVerifier({ targets: () => targets, anchors: memoryAnchors(), fetch }).verify(bytes);
    expect(report.verdict).toBe('invalid_signature');
  });

  it('a file saved again after signing is looked up by its signed revision', async () => {
    const tail = new TextEncoder().encode('\n99 0 obj\n<< /Note (edited) >>\nendobj\n%%EOF\n');
    const original = read('v2.pdf');
    const bytes = new Uint8Array(original.length + tail.length);
    bytes.set(original);
    bytes.set(tail, original.length);
    const { fetch, calls } = mockFetch({ [lookup(A)]: { body: answer('signature_valid_file_changed') } });

    const report = await new PdfVerifier({ targets: () => [targets[0]], anchors: memoryAnchors(), fetch }).verify(bytes);

    expect(report.verdict).toBe('signature_valid_file_changed');
    const body = JSON.parse(String(calls.find((c) => c.url === lookup(A))!.init.body));
    expect(body.signed_revision_sha256).toBe(hashes.sha256['v2.pdf']);
    expect(body.sha256).not.toBe(hashes.sha256['v2.pdf']);
  });

  it('with nothing paired, checks locally only and asks no one', async () => {
    const { fetch, calls } = mockFetch({});
    const report = await new PdfVerifier({ targets: () => [], anchors: memoryAnchors(), fetch }).verify(read('v2.pdf'));

    expect(report.paired).toBe(false);
    expect(report.verdict).toBe('lookup_failed');
    expect(report.inspection.signature).toMatchObject({ intact: true, trusted: null });
    expect(calls).toEqual([]);
  });
});

describe('readPdfFile', () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await mkdtemp(path.join(tmpdir(), 'agent-verify-'));
  });
  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it('reads a PDF by its bytes, whatever it is called', async () => {
    const file = path.join(tmp, 'report');
    await writeFile(file, read('v2.pdf'));
    const pdf = await readPdfFile(file);
    expect(pdf.name).toBe('report');
    expect(pdf.size).toBe(read('v2.pdf').length);
  });

  it.each([
    ['not a PDF', 'not_pdf', async (f: string) => writeFile(f, 'MZ\x90\x00 pretending.pdf')],
    ['empty', 'empty', async (f: string) => writeFile(f, '')],
    ['too large', 'too_large', async (f: string) => writeFile(f, `%PDF-1.4\n${'x'.repeat(2048)}`)],
  ])('refuses a file that is %s', async (_name, code, make) => {
    const file = path.join(tmp, 'x.pdf');
    await make(file);
    await expect(readPdfFile(file, 1024)).rejects.toMatchObject({ code });
  });

  it('refuses folders, missing files and relative paths', async () => {
    await expect(readPdfFile(tmp)).rejects.toMatchObject({ code: 'not_a_file' });
    await expect(readPdfFile(path.join(tmp, 'missing.pdf'))).rejects.toMatchObject({ code: 'not_found' });
    await expect(readPdfFile('relative.pdf')).rejects.toMatchObject({ code: 'not_found' });
  });
});

describe('Store trust anchors', () => {
  let tmp: string;
  const server: PairedServer = {
    id: 'amp',
    name: 'UPLB Signature',
    origin: A,
    salt: 's',
    userId: '1',
    userName: 'Ana',
    deviceUuid: 'd',
    deviceLabel: 'Mac',
    identityKeyId: 'i',
    sessionKeyId: 's',
    algorithm: 'ES256',
    protection: 'secure_enclave',
    userPresence: true,
    pairedAt: '2026-10-01T00:00:00.000Z',
  };
  beforeEach(async () => {
    tmp = await mkdtemp(path.join(tmpdir(), 'agent-anchors-'));
  });
  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it('pins per paired origin, keeps the first pin, and survives a restart', async () => {
    const store = new Store(tmp, fakeCipher);
    await store.load();
    expect(await store.pinTrustAnchor(A, CA)).toBeNull(); // nothing paired there yet
    await store.save(server, 't');
    expect((await store.pinTrustAnchor(A, CA))?.pem).toBe(CA);
    expect((await store.pinTrustAnchor(A, OTHER_CA))?.pem).toBe(CA);

    const again = new Store(tmp, fakeCipher);
    await again.load();
    expect(again.trustAnchor(A)?.pem).toBe(CA);
    expect(JSON.parse(await readFile(path.join(tmp, 'trust-anchors.json'), 'utf8')).anchors[A].pem).toBe(CA);
  });

  it('re-pins after pairing again, and forgets the pin when the last pairing there goes', async () => {
    const store = new Store(tmp, fakeCipher);
    await store.load();
    await store.save(server, 't');
    await store.pinTrustAnchor(A, CA);
    await store.update({ ...server, userName: 'Ana B.' });
    expect(store.trustAnchor(A)).not.toBeNull();

    await store.save({ ...server, pairedAt: '2026-10-02T00:00:00.000Z' }, 't2');
    expect(store.trustAnchor(A)).toBeNull();

    await store.pinTrustAnchor(A, CA);
    await store.remove('amp');
    expect(store.trustAnchor(A)).toBeNull();
    expect(store.trustAnchor('__proto__')).toBeNull();
  });
});
