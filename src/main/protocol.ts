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

/**
 * "Is this the computer you're paired on?" The web page opens it before it
 * lets someone sign; the agent answers by reporting in to the server. Same
 * shape and trust as a job link: an opaque id, a one-time token, a paired
 * server's id. It carries no content and needs no confirmation.
 */
export interface PresenceLink {
  kind: 'presence';
  checkId: string;
  token: string;
  serverId: string;
}

/**
 * Usernameless sign-in: the browser shows a match code and opens this link.
 * Same shape and trust as a job link; the paired device, not the page,
 * decides who signs in.
 */
export interface LoginLink {
  kind: 'login';
  challengeId: string;
  token: string;
  serverId: string;
}

export interface PairLink {
  kind: 'pair';
  origin: string;
  code: string;
}

export type AgentLink = JobLink | PresenceLink | LoginLink | PairLink;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/; // 32 random bytes, base64url, no padding
const SERVER_ID = /^[A-Za-z0-9_-]{1,64}$/;
// 8 characters from an unambiguous alphabet (no 0/O, 1/I/L), shown as XXXX-XXXX.
const USER_CODE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-?[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$/;

export interface OriginPolicy {
  /**
   * Allow plain http:// for loopback and private-network hosts, so the agent
   * can test against a project on this machine or another one on the same
   * LAN. Unpackaged builds (npm run dev) and tests only.
   */
  allowInsecureLocalNetwork?: boolean;
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

  if (segments[0] === 'presence' && segments.length === 2) {
    if (!onlyParams(params, ['t', 's'])) return null;
    const checkId = segments[1].toLowerCase();
    const token = params.get('t') ?? '';
    const serverId = params.get('s') ?? '';
    if (!UUID.test(checkId) || !TOKEN.test(token) || !SERVER_ID.test(serverId)) return null;
    return { kind: 'presence', checkId, token, serverId };
  }

  if (segments[0] === 'login' && segments.length === 2) {
    if (!onlyParams(params, ['t', 's'])) return null;
    const challengeId = segments[1].toLowerCase();
    const token = params.get('t') ?? '';
    const serverId = params.get('s') ?? '';
    if (!UUID.test(challengeId) || !TOKEN.test(token) || !SERVER_ID.test(serverId)) return null;
    return { kind: 'login', challengeId, token, serverId };
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

/** A lowercase UUID, as in links. For ids that come from a server, not a link. */
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
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
 * local-network hosts when the policy allows it. Paths, credentials, queries
 * and fragments are rejected rather than silently dropped.
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
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:' && policy.allowInsecureLocalNetwork && isLocalNetworkHost(url.hostname)) return url.origin;
  return null;
}

// Names that never resolve on the public internet: loopback, mDNS (.local),
// and the reserved .test / .localhost TLDs that Herd, Valet and friends use.
const LOCAL_NAME = /^(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:localhost|local|test))$/;

/**
 * Loopback, private (RFC 1918), link-local and IPv6 unique-local addresses,
 * plus local-only names. `hostname` is as WHATWG URL normalizes it: lower
 * case, IPv4 in dotted decimal, IPv6 in brackets.
 */
export function isLocalNetworkHost(hostname: string): boolean {
  if (LOCAL_NAME.test(hostname)) return true;

  const v4 = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }

  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    const v6 = hostname.slice(1, -1);
    // ::1 loopback, fc00::/7 unique local, fe80::/10 link-local.
    return v6 === '::1' || /^f[cd][0-9a-f]{2}:/.test(v6) || /^fe[89ab][0-9a-f]:/.test(v6);
  }
  return false;
}

/** Finds a kukuxsign:// link in process argv (Windows second-instance / first launch). */
export function linkFromArgv(argv: string[]): string | null {
  return argv.find((arg) => arg.startsWith(`${SCHEME}://`)) ?? null;
}
