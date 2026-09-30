// kukuxsign:// link parsing (desktop-agent-plan.md §7.2).
//
// Link parameters are never trusted: a job link carries only an opaque job id,
// a one-time token and the id of an already-paired server. The agent then
// fetches the job itself from that server's stored origin. Anything that
// doesn't match exactly is dropped.

export const SCHEME = 'kukuxsign';

export interface JobLink {
  kind: 'job';
  jobId: string;
  token: string;
  serverId: string;
}

export interface PairLink {
  kind: 'pair';
  origin: string;
  code: string;
}

export type AgentLink = JobLink | PairLink;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/; // 32 random bytes, base64url, no padding
const SERVER_ID = /^[A-Za-z0-9_-]{1,64}$/;
// 8 characters from an unambiguous alphabet (no 0/O, 1/I/L), shown as XXXX-XXXX.
const USER_CODE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-?[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$/;

export interface OriginPolicy {
  /** Allow http://localhost and http://127.0.0.1 (development and tests only). */
  allowInsecureLocalhost?: boolean;
}

export function parseLink(raw: string, policy: OriginPolicy = {}): AgentLink | null {
  if (typeof raw !== 'string' || raw.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== `${SCHEME}:` || url.username || url.password || url.port || url.hash) return null;

  // new URL() puts the first segment of kukuxsign://job/<uuid> in `host`.
  const segments = [url.host, ...url.pathname.split('/').filter(Boolean)];
  const params = url.searchParams;

  if (segments[0] === 'job' && segments.length === 2) {
    if (!onlyParams(params, ['t', 's'])) return null;
    const jobId = segments[1].toLowerCase();
    const token = params.get('t') ?? '';
    const serverId = params.get('s') ?? '';
    if (!UUID.test(jobId) || !TOKEN.test(token) || !SERVER_ID.test(serverId)) return null;
    return { kind: 'job', jobId, token, serverId };
  }

  if (segments[0] === 'pair' && segments.length === 1) {
    if (!onlyParams(params, ['o', 'c'])) return null;
    const origin = normalizeOrigin(params.get('o') ?? '', policy);
    const code = normalizeUserCode(params.get('c') ?? '');
    if (!origin || !code) return null;
    return { kind: 'pair', origin, code };
  }

  return null;
}

function onlyParams(params: URLSearchParams, allowed: string[]): boolean {
  const keys = [...params.keys()];
  return keys.length === allowed.length && allowed.every((k) => params.getAll(k).length === 1);
}

/** Returns "XXXX-XXXX" or null. Accepts lower case, spaces and a missing dash. */
export function normalizeUserCode(input: string): string | null {
  const compact = input.toUpperCase().replace(/[\s-]/g, '');
  if (!USER_CODE.test(compact)) return null;
  return `${compact.slice(0, 4)}-${compact.slice(4)}`;
}

/**
 * Returns the bare origin (scheme://host[:port]) or null. HTTPS only, except
 * localhost when the policy allows it. Paths, credentials, queries and
 * fragments are rejected rather than silently dropped.
 */
export function normalizeOrigin(input: string, policy: OriginPolicy = {}): string | null {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    return null;
  }
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  const localhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:' && localhost && policy.allowInsecureLocalhost) return url.origin;
  return null;
}

/** Finds a kukuxsign:// link in process argv (Windows second-instance / first launch). */
export function linkFromArgv(argv: string[]): string | null {
  return argv.find((arg) => arg.startsWith(`${SCHEME}://`)) ?? null;
}
