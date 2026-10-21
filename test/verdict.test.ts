// How the agent turns two checks into one answer.
//
// Ported from tests/js/verdict.test.mjs in kukux/digital-signature. The rules
// that matter: an exact record match always wins; a broken embedded signature
// outranks "not issued"; and a failed lookup is never shown as "not issued",
// because "we couldn't ask" and "we asked and it isn't ours" send the holder
// off to do very different things.
import { describe, expect, it } from 'vitest';

import { COPY, combineVerdict, copyTitle, describeEmbedded, describeSlot, type Verdict } from '../src/shared/verdict';

const intact = { signature: { intact: true, trusted: true, signer: 'Ben', coversWholeFile: true } };
const broken = { signature: { intact: false, trusted: null, signer: 'Ben', coversWholeFile: true } };
const unsigned = { signature: null };

describe('verdict', () => {
  it('an exact record match wins over everything the file says', () => {
    for (const verdict of ['complete', 'in_progress', 'superseded', 'withdrawn']) {
      expect(combineVerdict(broken, { verdict })).toBe(verdict);
      expect(combineVerdict(unsigned, { verdict })).toBe(verdict);
    }
  });

  it('a broken signature outranks "not issued" and "changed after signing"', () => {
    expect(combineVerdict(broken, { verdict: 'not_issued' })).toBe('invalid_signature');
    expect(combineVerdict(broken, { verdict: 'signature_valid_file_changed' })).toBe('invalid_signature');
  });

  it('an intact signature on a file saved since is "changed after signing"', () => {
    expect(combineVerdict(intact, { verdict: 'signature_valid_file_changed' })).toBe('signature_valid_file_changed');
  });

  it('no match and no signature is "not issued"', () => {
    expect(combineVerdict(unsigned, { verdict: 'not_issued' })).toBe('not_issued');
    expect(combineVerdict(intact, { verdict: 'not_issued' })).toBe('not_issued');
  });

  it('a failed lookup is never reported as "not issued"', () => {
    expect(combineVerdict(intact, null)).toBe('lookup_failed');
    expect(combineVerdict(unsigned, null)).toBe('lookup_failed');
    // But a broken signature is still broken, whether or not the server answered.
    expect(combineVerdict(broken, null)).toBe('invalid_signature');
  });

  it('every verdict the agent can reach has words', () => {
    const context = { issuer: 'UPLB Performance', document: { signed: 2, required: 4 } };
    const keys: Verdict[] = [
      'complete',
      'in_progress',
      'superseded',
      'withdrawn',
      'signature_valid_file_changed',
      'invalid_signature',
      'not_issued',
      'lookup_failed',
    ];

    for (const key of keys) {
      expect(COPY[key], key).toBeTruthy();
      expect(copyTitle(key, context).length, `${key} title`).toBeGreaterThan(0);
      expect(COPY[key].lede(context).length, `${key} lede`).toBeGreaterThan(0);
    }

    expect(COPY.in_progress.lede(context)).toMatch(/2 of 4/);
    expect(copyTitle('not_issued', context)).toBe('Not issued by UPLB Performance');
  });

  it('a slot signed after this copy is not shown as signed on it', () => {
    expect(describeSlot({ state: 'signed_later' }).text).toBe('Signed in a later copy, not this one');
    expect(describeSlot({ state: 'signed', signer: 'Ana' }).text).toBe('Signed by Ana');
    expect(describeSlot({ state: 'signed', signer: 'Ana', certificate: 'revoked' }).chip?.text).toBe('Certificate since revoked');
  });

  it('describes the embedded signature without overclaiming trust', () => {
    const rows = Object.fromEntries(describeEmbedded({ signature: { intact: true, trusted: null, signer: 'Ben', coversWholeFile: false } }, 'X'));

    expect(rows['Certificate']).toBe('Not checked');
    expect(rows['Saved since signing']).toBeTruthy();
    expect(Object.fromEntries(describeEmbedded(unsigned, 'X'))['Digital signature']).toBe('None in this file');
  });

  it('says the file alone vouches only for its digital signatures when the record could not be asked', () => {
    const one = { signature: intact.signature, signatures: [intact.signature] };
    const rows = Object.fromEntries(describeEmbedded(one, 'X'));

    expect(rows['Other signatures']).toMatch(/one digital signature, the last signer's/);
    // When the record answered, it lists every slot itself.
    expect(Object.fromEntries(describeEmbedded(one, 'X', { recordChecked: true }))['Other signatures']).toBeUndefined();
    expect(Object.fromEntries(describeEmbedded(unsigned, 'X'))['Signatures on the page']).toMatch(/only the record can confirm/i);
  });

  it('numbers the rows when a file carries several digital signatures', () => {
    const ana = { intact: true, trusted: true, signer: 'Ana', coversWholeFile: false };
    const ben = { intact: true, trusted: true, signer: 'Ben', coversWholeFile: true };

    expect(describeEmbedded({ signature: ben, signatures: [ana, ben] }, 'X', { recordChecked: true }).slice(0, 2)).toEqual([
      ['Digital signature 1 of 2', 'Intact, made by Ana'],
      ['Digital signature 2 of 2', 'Intact, made by Ben'],
    ]);
  });
});
