import { describe, expect, it } from 'vitest';

import type { AgentJob } from '../src/main/api';
import { validateJob, validateLogin } from '../src/main/jobs';
import type { JobLink } from '../src/main/protocol';
import type { PairedServer } from '../src/main/store';

const UUID = '0b7a4f5e-1c2d-4e3f-8a9b-0c1d2e3f4a5b';
const server = { id: 'hub', userId: '42' } as PairedServer;
const link: JobLink = { kind: 'job', jobId: UUID, token: 'x'.repeat(43), serverId: 'hub' };

const job = (overrides: Partial<AgentJob> = {}): AgentJob => ({
  uuid: UUID,
  purpose: 'sign_receipt',
  status: 'claimed',
  nonce: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
  user_id: '42',
  payload_hash: 'a'.repeat(64),
  document: { title: 'Leave form' },
  signer: { name: 'Juan Dela Cruz' },
  expires_at: '2026-10-08T00:00:00Z',
  ...overrides,
});

const login = (overrides: Partial<AgentJob> = {}): AgentJob =>
  job({
    purpose: 'login',
    document: { title: 'Sign in to performance' },
    login: { match_code: '47-12', browser: 'Chrome on macOS', ip: '10.1.2.3' },
    ...overrides,
  });

describe('validateJob', () => {
  it('accepts a job without the hub fields, as standalone servers send it', () => {
    expect(validateJob(job(), link, server)).toBeNull();
    expect(validateJob(job({ requesting_app: null as unknown as undefined }), link, server)).toBeNull();
  });

  it('accepts a requesting app that passes the text checks', () => {
    expect(validateJob(job({ requesting_app: { name: 'performance' } }), link, server)).toBeNull();
  });

  it.each([
    ['an empty name', { name: '  ' }],
    ['a long name', { name: 'x'.repeat(301) }],
    ['a non-string name', { name: 7 }],
    ['a bare string', 'performance'],
  ])('refuses a requesting app with %s', (_why, requestingApp) => {
    expect(validateJob(job({ requesting_app: requestingApp as AgentJob['requesting_app'] }), link, server)).toMatch(/requesting app/);
  });

  it('accepts a transfer only with its name and computer', () => {
    const transfer = { name: 'Juan Dela Cruz', device: 'MacBook Air' };
    expect(validateJob(job({ purpose: 'transfer', transfer }), link, server)).toBeNull();
    expect(validateJob(job({ purpose: 'transfer' }), link, server)).toMatch(/transfer/);
    expect(validateJob(job({ purpose: 'transfer', transfer: { ...transfer, device: '' } }), link, server)).toMatch(/transfer/);
  });

  it('never accepts a sign-in through a job link', () => {
    expect(validateJob(login(), link, server)).toMatch(/unsupported purpose: login/);
  });
});

describe('validateLogin', () => {
  it('accepts a sign-in, even before the account has a name', () => {
    expect(validateLogin(login(), server)).toBeNull();
    expect(validateLogin(login({ signer: { name: '' } }), server)).toBeNull();
  });

  it.each([
    ['another purpose', { purpose: 'sign_receipt' }],
    ['another user', { user_id: '7' }],
    ['a job id that is not a uuid', { uuid: '../jobs/x' }],
    ['no title', { document: { title: '' } }],
    ['no login block', { login: undefined }],
    ['a bad match code', { login: { match_code: '4712', browser: '', ip: '' } }],
    ['a long browser', { login: { match_code: '47-12', browser: 'x'.repeat(301), ip: '' } }],
    ['a bad requesting app', { requesting_app: { name: '' } }],
    ['a bad nonce', { nonce: 'has|pipe' }],
  ])('refuses %s', (_why, overrides) => {
    expect(validateLogin(login(overrides as Partial<AgentJob>), server)).not.toBeNull();
  });
});
