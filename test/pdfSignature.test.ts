// The local half of document verification, against real signed PDFs.
//
// Ported from tests/js/pdfSignature.test.mjs in kukux/digital-signature, with
// the same fixtures (test/fixtures/verification, made by the package's
// tests/Fixtures/verification/generate.php). They are signed by the package's
// own FpdiDriver, so these tests read the byte layout TCPDF really writes.
// Each case is something a holder could open with the agent: the genuine
// file, a file signed by a CA we don't trust, a file edited inside what was
// signed, and a file saved again after signing.
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { findLastSignature, findSignatures, inspectPdf, parsePemCertificates, sha256Hex } from '../src/main/verify/pdfSignature';

const dir = path.join(__dirname, 'fixtures', 'verification');
const read = (name: string) => new Uint8Array(readFileSync(path.join(dir, name)));
const fixtures = JSON.parse(readFileSync(path.join(dir, 'hashes.json'), 'utf8')) as {
  sha256: Record<string, string>;
  signers: Record<string, string | string[]>;
};

const trusted = parsePemCertificates(readFileSync(path.join(dir, 'ca.pem'), 'utf8'));
const stranger = parsePemCertificates(readFileSync(path.join(dir, 'other-ca.pem'), 'utf8'));

/** Append bytes the way an incremental save does: after %%EOF, untouched before. */
function appendUpdate(bytes: Uint8Array): Uint8Array {
  const tail = new TextEncoder().encode('\n99 0 obj\n<< /Note (edited after signing) >>\nendobj\n%%EOF\n');
  const out = new Uint8Array(bytes.length + tail.length);
  out.set(bytes, 0);
  out.set(tail, bytes.length);
  return out;
}

describe('pdfSignature', () => {
  it('fingerprints the whole file with the hash the server stored', async () => {
    for (const name of ['base.pdf', 'v1.pdf', 'v2.pdf']) {
      expect(await sha256Hex(read(name)), name).toBe(fixtures.sha256[name]);
    }
  });

  it('finds no signature in the unsigned base document', async () => {
    const result = await inspectPdf(read('base.pdf'), trusted);

    expect(result.signature).toBeNull();
    expect(result.signedRevisionSha256).toBeNull();
  });

  it('verifies the last signer of a progressively signed file against the trusted CA', async () => {
    const result = await inspectPdf(read('v2.pdf'), trusted);

    expect(result.signature?.intact).toBe(true);
    expect(result.signature?.trusted).toBe(true);
    expect(result.signature?.signer).toBe(fixtures.signers['v2.pdf']);
    expect(result.signature?.coversWholeFile).toBe(true);
    expect(result.signedRevisionSha256).toBe(result.sha256);
    expect(result.signature?.signedAt, 'signing time read from the signed attributes').toBeTruthy();
  });

  it("reads each version's own signer", async () => {
    const result = await inspectPdf(read('v1.pdf'), trusted);

    expect(result.signature?.signer).toBe(fixtures.signers['v1.pdf']);
    expect(result.signature?.trusted).toBe(true);
  });

  it('keeps "intact" and "trusted" apart for a CA we do not trust', async () => {
    const result = await inspectPdf(read('v2.pdf'), stranger);

    expect(result.signature?.intact).toBe(true);
    expect(result.signature?.trusted).toBe(false);
    expect(result.signature?.error).toBe('untrusted_chain');
  });

  it('reports trust as unchecked, not failed, when no CA could be fetched', async () => {
    const result = await inspectPdf(read('v2.pdf'), []);

    expect(result.signature?.intact).toBe(true);
    expect(result.signature?.trusted).toBeNull();
  });

  it('breaks when a signed byte is changed', async () => {
    const bytes = read('v2.pdf');
    const { byteRange } = findLastSignature(bytes)!;

    // A byte well inside the first signed segment, past the header.
    const at = Math.floor(byteRange[1] / 2);
    bytes[at] = bytes[at] === 0x20 ? 0x21 : 0x20;

    const result = await inspectPdf(bytes, trusted);

    expect(result.sha256).not.toBe(fixtures.sha256['v2.pdf']);
    expect(result.signature?.intact).toBe(false);
    expect(result.signature?.error).toBe('signature_mismatch');
  });

  it('recovers the signed copy from a file saved again after signing', async () => {
    const result = await inspectPdf(appendUpdate(read('v2.pdf')), trusted);

    expect(result.sha256, 'whole file no longer matches').not.toBe(fixtures.sha256['v2.pdf']);
    expect(result.signedRevisionSha256, 'but its signed prefix does').toBe(fixtures.sha256['v2.pdf']);
    expect(result.signature?.coversWholeFile).toBe(false);
    expect(result.signature?.intact).toBe(true);
  });

  it("a progressively signed file carries one digital signature, the last signer's", async () => {
    const result = await inspectPdf(read('v2.pdf'), trusted);

    expect(result.signatures).toHaveLength(1);
    expect(result.signatures[0].signer).toBe(fixtures.signers['v2.pdf']);
  });

  it('checks every signature in a file that kept them all', async () => {
    const result = await inspectPdf(read('two-signatures.pdf'), trusted);

    expect(result.signatures.map((s) => s.signer)).toEqual(fixtures.signers['two-signatures.pdf']);
    expect(result.signatures.every((s) => s.intact && s.trusted === true)).toBe(true);
    // Only the later one covers the whole file; the verdict turns on it.
    expect(result.signatures.map((s) => s.coversWholeFile)).toEqual([false, true]);
    expect(result.signature?.signer).toBe('Ben Accepted');
    expect(result.signedRevisionSha256).toBe(result.sha256);
  });

  it('lists signatures in the order they were added', () => {
    const found = findSignatures(read('two-signatures.pdf'));

    expect(found).toHaveLength(2);
    expect(found[0].revisionEnd).toBeLessThan(found[1].revisionEnd);
    expect(findLastSignature(read('two-signatures.pdf'))?.revisionEnd).toBe(found[1].revisionEnd);
  });

  it('ignores a /ByteRange that is only text and points at no signature', () => {
    const decoy = new TextEncoder().encode('%PDF-1.4\n(/ByteRange [0 10 20 5]) is just a string here\n%%EOF\n');

    expect(findLastSignature(decoy)).toBeNull();
  });

  it('ignores a /ByteRange that runs past the end of the file', () => {
    const decoy = new TextEncoder().encode('%PDF-1.4\n/ByteRange [0 12 14 999999] <00>\n%%EOF\n');

    expect(findLastSignature(decoy)).toBeNull();
  });

  it('hashes a view into a larger buffer by its own bytes only', async () => {
    const bytes = read('v1.pdf');
    const padded = new Uint8Array(bytes.length + 16);
    padded.set(bytes, 8);

    expect(await sha256Hex(padded.subarray(8, 8 + bytes.length))).toBe(fixtures.sha256['v1.pdf']);
  });
});
