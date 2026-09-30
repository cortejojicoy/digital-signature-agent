import { createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { AgentApi, ApiError, type Credentials, type FetchLike } from '../src/main/api';
import { requestPayloadHash } from '../src/main/canonical';

function recordingFetch(response: { status?: number; body?: unknown } = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return new Response(response.body === undefined ? '{}' : JSON.stringify(response.body), {
      status: response.status ?? 200,
    });
  };
  return { fetch, calls };
}

function credentials(): Credentials & { publicKey: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    token: 'secret-token',
    userId: '42',
    publicKey: publicKey.export({ format: 'der', type: 'spki' }),
    signWithSessionKey: async (m) => sign('sha256', m, { key: privateKey, dsaEncoding: 'der' }),
  };
}

describe('AgentApi', () => {
  it('refuses non-HTTPS origins', () => {
    expect(() => new AgentApi({ origin: 'http://sign.example.gov.ph', agentVersion: '1.0.0' })).toThrow();
    expect(() => new AgentApi({ origin: 'https://sign.example.gov.ph/path', agentVersion: '1.0.0' })).toThrow();
  });

  it('sends unauthenticated pairing calls to the pinned origin without following redirects', async () => {
    const { fetch, calls } = recordingFetch({ body: { pairing: 'p' } });
    const api = new AgentApi({ origin: 'https://sign.example.gov.ph', agentVersion: '1.2.3', fetch });
    await api.lookupPairing('K7QM-2XPD');
    expect(calls[0].url).toBe('https://sign.example.gov.ph/signature/agent/pairings/lookup');
    expect(calls[0].init.redirect).toBe('error');
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['X-Agent-Version']).toBe('1.2.3');
    expect(headers.Authorization).toBeUndefined();
  });

  it('keeps crafted ids inside the API path', async () => {
    const { fetch, calls } = recordingFetch();
    const api = new AgentApi({ origin: 'https://sign.example.gov.ph', agentVersion: '1.0.0', fetch });
    await api.pollPairing('../../evil?x=1', 's');
    expect(calls[0].url).toBe('https://sign.example.gov.ph/signature/agent/pairings/..%2F..%2Fevil%3Fx%3D1/poll');
  });

  it('signs authenticated requests with the session key (X-Agent-Proof)', async () => {
    const { fetch, calls } = recordingFetch({ body: { status: 'completed' } });
    const now = 1_767_225_600_000;
    const api = new AgentApi({ origin: 'https://sign.example.gov.ph', agentVersion: '1.0.0', fetch, now: () => now });
    const creds = credentials();
    const jobId = '0b7a4f5e-1c2d-4e3f-8a9b-0c1d2e3f4a5b';
    await api.completeJob(creds, jobId, 'PROOF');

    const { init } = calls[0];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer secret-token');
    expect(headers['X-Agent-Timestamp']).toBe('1767225600');
    expect(headers['X-Agent-Nonce']).toMatch(/^[A-Za-z0-9_-]{22}$/);

    const body = String(init.body);
    const payload = requestPayloadHash('POST', `/signature/agent/jobs/${jobId}/complete`, body, '1767225600');
    const message = `v1|request|${headers['X-Agent-Nonce']}|42|${payload}`;
    const key = createPublicKey({ key: creds.publicKey, format: 'der', type: 'spki' });
    expect(verify('sha256', Buffer.from(message), { key, dsaEncoding: 'der' }, Buffer.from(headers['X-Agent-Proof'], 'base64'))).toBe(true);
  });

  it('maps error bodies to ApiError, including min_version refusals', async () => {
    const { fetch } = recordingFetch({ status: 426, body: { error: { code: 'agent_outdated', message: 'Update' } } });
    const api = new AgentApi({ origin: 'https://sign.example.gov.ph', agentVersion: '0.1.0', fetch });
    const err = await api.lookupPairing('K7QM-2XPD').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.outdated).toBe(true);
    expect(err.code).toBe('agent_outdated');
  });
});
