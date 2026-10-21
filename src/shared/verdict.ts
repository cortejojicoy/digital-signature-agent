// One answer from two checks: what the file says about itself
// (main/verify/pdfSignature.ts inspectPdf) and what the record says about the
// file (POST /signature/verify/lookup).
//
// Mirrors resources/js/verify/verdict.js in kukux/digital-signature, which the
// web verify page uses. Keep the two in step: the rules and every sentence
// here should read the same in the browser and in the agent.
//
// The record decides whenever it recognises the exact bytes: a file that is
// byte-for-byte a version the system issued is that version, whatever else
// is true. Only when it doesn't does the local check get a say, and a broken
// embedded signature outranks "not issued" because it tells the holder more:
// this file was signed and then altered.
//
// Pure, so the main process and the renderer share it (test/verdict.test.ts).

export const RECORD_VERDICTS = ['complete', 'in_progress', 'superseded', 'withdrawn'] as const;

/** What the lookup endpoint can answer. */
export const LOOKUP_VERDICTS = [...RECORD_VERDICTS, 'signature_valid_file_changed', 'not_issued'] as const;

export type RecordVerdict = (typeof RECORD_VERDICTS)[number];
export type LookupVerdict = (typeof LOOKUP_VERDICTS)[number];
/** A key of COPY. */
export type Verdict = LookupVerdict | 'invalid_signature' | 'lookup_failed';

/** The last signature in the file, as pdfSignature.verifyCms reads it. */
export interface EmbeddedSignature {
  intact: boolean;
  /** null: no trusted CA to check against ("not checked", not "untrusted"). */
  trusted: boolean | null;
  signer: string | null;
  signedAt: string | null;
  error: string | null;
  /** false: bytes were appended after the last signature. */
  coversWholeFile: boolean;
}

export interface Inspection {
  sha256: string;
  /** The bytes up to the end of the last signature; null with no signature. */
  signedRevisionSha256: string | null;
  /** The last signature: the one the verdict turns on. */
  signature: EmbeddedSignature | null;
  /** Every signature in the file, oldest first (one, for a progressively signed PDF). */
  signatures: EmbeddedSignature[];
}

export type SlotState = 'signed' | 'signed_later' | 'declined' | 'pending';
export type CertificateState = 'valid' | 'revoked' | 'unknown' | 'unchecked';

export interface LookupSlot {
  slot: string;
  label: string;
  state: SlotState;
  signer: string | null;
  signed_at: string | null;
  certificate: CertificateState | null;
}

export interface LookupDocument {
  title: string | null;
  version: number;
  versions: number;
  signed: number;
  required: number;
  status: string;
}

/** A 200 from POST /signature/verify/lookup. */
export interface LookupRecord {
  verdict: LookupVerdict;
  issuer: string;
  document: LookupDocument | null;
  slots: LookupSlot[];
}

export function isRecordVerdict(verdict: string): verdict is RecordVerdict {
  return (RECORD_VERDICTS as readonly string[]).includes(verdict);
}

/**
 * @param inspection what the file says about itself
 * @param record     null when the lookup failed
 */
export function combineVerdict(inspection: { signature: { intact: boolean } | null }, record: { verdict: string } | null): Verdict {
  if (record && isRecordVerdict(record.verdict)) {
    return record.verdict;
  }

  if (inspection.signature && inspection.signature.intact === false) {
    return 'invalid_signature';
  }

  if (record && record.verdict === 'signature_valid_file_changed') {
    return 'signature_valid_file_changed';
  }

  if (record === null) {
    return 'lookup_failed';
  }

  return 'not_issued';
}

export type Tone = 'ok' | 'warn' | 'bad' | 'info';

export interface CopyContext {
  issuer: string;
  document?: Pick<LookupDocument, 'signed' | 'required'> | null;
}

interface Copy {
  tone: Tone;
  mark: string;
  title: string | ((context: CopyContext) => string);
  lede: (context: CopyContext) => string;
}

/**
 * What to say for each verdict. `tone` picks the colour and mark; the text is
 * written for the person holding the file, not for whoever built the system.
 */
export const COPY: Record<Verdict, Copy> = {
  complete: {
    tone: 'ok',
    mark: '✓',
    title: 'Signed copy of record',
    lede: ({ issuer }) => `This file is exactly the copy ${issuer} holds, and every signatory has signed it.`,
  },
  in_progress: {
    tone: 'warn',
    mark: '…',
    title: 'Genuine, but not finished',
    lede: ({ document }) =>
      `This is a real copy, but only ${document?.signed} of ${document?.required} signatures are on it. It isn't a finished document yet.`,
  },
  superseded: {
    tone: 'warn',
    mark: '↻',
    title: 'Genuine earlier copy',
    lede: () => 'This is a real copy, but more signatures were added after it. Ask for the latest copy.',
  },
  withdrawn: {
    tone: 'warn',
    mark: '–',
    title: 'Signing was stopped',
    lede: () => 'This is a real copy, but signing was cancelled or ran out of time before everyone signed.',
  },
  signature_valid_file_changed: {
    tone: 'bad',
    mark: '!',
    title: 'Changed after signing',
    lede: () =>
      'The signatures are real, but this file was edited and saved after the last one. What you see may not be what was signed.',
  },
  invalid_signature: {
    tone: 'bad',
    mark: '!',
    title: 'The signature is broken',
    lede: () => "The digital signature in this file doesn't match its contents, so the file was altered after it was signed.",
  },
  not_issued: {
    tone: 'bad',
    mark: '✕',
    title: ({ issuer }) => `Not issued by ${issuer}`,
    lede: ({ issuer }) => `This file doesn't match any document ${issuer} issued. Treat any signatures shown on it as unverified.`,
  },
  lookup_failed: {
    tone: 'info',
    mark: '?',
    title: "Couldn't check the record",
    lede: () => "The server didn't answer, so this only shows what the file says about itself. Try again in a moment.",
  },
};

/** A verdict's title, whether it's fixed or depends on the issuer. */
export function copyTitle(verdict: Verdict, context: CopyContext): string {
  const title = COPY[verdict].title;
  return typeof title === 'function' ? title(context) : title;
}

export interface SlotDescription {
  text: string;
  chip: { tone: Tone; text: string } | null;
}

/** Plain-language state for one slot row, plus a chip for the certificate. */
export function describeSlot(slot: Pick<LookupSlot, 'state'> & Partial<Pick<LookupSlot, 'signer' | 'certificate'>>): SlotDescription {
  switch (slot.state) {
    case 'signed':
      return {
        text: `Signed by ${slot.signer ?? 'a signatory'}`,
        chip:
          slot.certificate === 'revoked'
            ? { tone: 'bad', text: 'Certificate since revoked' }
            : slot.certificate === 'unchecked'
              ? { tone: 'info', text: 'Certificate not checked' }
              : null,
      };
    case 'signed_later':
      return { text: 'Signed in a later copy, not this one', chip: null };
    case 'declined':
      return { text: 'Declined', chip: { tone: 'bad', text: 'Declined' } };
    default:
      return { text: 'Not signed yet', chip: null };
  }
}

/**
 * What the file's own digital signatures say, as label/value rows.
 *
 * One row for a single signature, numbered rows for several. Unless the
 * record answered (and so lists every slot itself), it also says how many
 * digital signatures the file carries: with progressive signing that is one,
 * the last signer's, and the signatures stamped before it are images the
 * file alone can't vouch for.
 */
export function describeEmbedded(
  inspection: {
    signature: Pick<EmbeddedSignature, 'intact' | 'trusted' | 'signer' | 'coversWholeFile'> | null;
    signatures?: Array<Pick<EmbeddedSignature, 'intact' | 'trusted' | 'signer' | 'coversWholeFile'>>;
  },
  issuer: string,
  { recordChecked = false }: { recordChecked?: boolean } = {},
): Array<[string, string]> {
  const signatures = inspection.signatures ?? (inspection.signature ? [inspection.signature] : []);
  const last = signatures.length > 0 ? signatures[signatures.length - 1] : null;
  const made = (s: Pick<EmbeddedSignature, 'intact' | 'signer'>) =>
    s.intact ? `Intact${s.signer ? `, made by ${s.signer}` : ''}` : "Broken: doesn't match the file";

  if (last === null) {
    return recordChecked
      ? [['Digital signature', 'None in this file']]
      : [
          ['Digital signature', 'None in this file'],
          ['Signatures on the page', 'Images only. Only the record can confirm who signed.'],
        ];
  }

  const rows: Array<[string, string]> =
    signatures.length === 1
      ? [['Digital signature', made(last)]]
      : signatures.map((s, i): [string, string] => [`Digital signature ${i + 1} of ${signatures.length}`, made(s)]);

  if (last.intact) {
    rows.push([
      'Certificate',
      last.trusted === true
        ? `Issued under ${issuer}'s certificate authority`
        : last.trusted === false
          ? "Issued by a certificate authority this system doesn't trust"
          : 'Not checked',
    ]);
  }

  if (!last.coversWholeFile) {
    rows.push(['Saved since signing', 'Yes, bytes were added after the last signature']);
  }

  if (!recordChecked) {
    rows.push([
      'Other signatures',
      signatures.length === 1
        ? "This file carries one digital signature, the last signer's. Any other signature on the page is an image that only the record can confirm."
        : `This file carries ${signatures.length} digital signatures. Any other signature on the page is an image that only the record can confirm.`,
    ]);
  }

  return rows;
}
