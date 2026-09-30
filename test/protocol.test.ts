import { describe, expect, it } from 'vitest';

import { linkFromArgv, normalizeOrigin, normalizeUserCode, parseLink } from '../src/main/protocol';

const UUID = '0b7a4f5e-1c2d-4e3f-8a9b-0c1d2e3f4a5b';
const TOKEN = 'fIb2Bzv4gKtSWoDpD9canXJryrxB47J3uR9y4Xkqz8w';

describe('parseLink', () => {
  it('accepts the one job link shape', () => {
    expect(parseLink(`kukuxsign://job/${UUID}?t=${TOKEN}&s=test-server`)).toEqual({
      kind: 'job',
      jobId: UUID,
      token: TOKEN,
      serverId: 'test-server',
    });
  });

  it.each([
    ['wrong scheme', `https://job/${UUID}?t=${TOKEN}&s=a`],
    ['bad uuid', `kukuxsign://job/not-a-uuid?t=${TOKEN}&s=a`],
    ['short token', `kukuxsign://job/${UUID}?t=abc&s=a`],
    ['token with padding', `kukuxsign://job/${UUID}?t=${TOKEN.slice(0, 42)}=&s=a`],
    ['missing server', `kukuxsign://job/${UUID}?t=${TOKEN}`],
    ['extra parameter', `kukuxsign://job/${UUID}?t=${TOKEN}&s=a&title=Pay%20me`],
    ['duplicate parameter', `kukuxsign://job/${UUID}?t=${TOKEN}&t=${TOKEN}&s=a`],
    ['extra path segment', `kukuxsign://job/${UUID}/x?t=${TOKEN}&s=a`],
    ['fragment', `kukuxsign://job/${UUID}?t=${TOKEN}&s=a#x`],
    ['credentials', `kukuxsign://user:pw@job/${UUID}?t=${TOKEN}&s=a`],
    ['unknown action', `kukuxsign://sign/${UUID}?t=${TOKEN}&s=a`],
    ['bad server id', `kukuxsign://job/${UUID}?t=${TOKEN}&s=a%2Fb`],
    ['not a url', 'hello'],
  ])('drops %s', (_name, raw) => {
    expect(parseLink(raw)).toBeNull();
  });

  it('accepts a pair link with an HTTPS origin', () => {
    expect(parseLink('kukuxsign://pair?o=https%3A%2F%2Fsign.example.gov.ph&c=k7qm2xpd')).toEqual({
      kind: 'pair',
      origin: 'https://sign.example.gov.ph',
      code: 'K7QM-2XPD',
    });
  });

  it('refuses plain-HTTP pair links unless localhost is allowed', () => {
    const raw = 'kukuxsign://pair?o=http%3A%2F%2F127.0.0.1%3A8787&c=K7QM-2XPD';
    expect(parseLink(raw)).toBeNull();
    expect(parseLink(raw, { allowInsecureLocalhost: true })).toMatchObject({ origin: 'http://127.0.0.1:8787' });
    expect(parseLink('kukuxsign://pair?o=http%3A%2F%2Fevil.test&c=K7QM-2XPD', { allowInsecureLocalhost: true })).toBeNull();
  });
});

describe('normalizeOrigin', () => {
  it.each([
    ['https://sign.example.gov.ph', 'https://sign.example.gov.ph'],
    ['https://sign.example.gov.ph/', 'https://sign.example.gov.ph'],
    [' https://Sign.Example.gov.ph:8443 ', 'https://sign.example.gov.ph:8443'],
  ])('normalizes %s', (input, expected) => {
    expect(normalizeOrigin(input)).toBe(expected);
  });

  it.each(['http://sign.example.gov.ph', 'https://sign.example.gov.ph/admin', 'https://u:p@x.test', 'https://x.test/?a=1', 'ftp://x.test', 'x.test'])(
    'rejects %s',
    (input) => {
      expect(normalizeOrigin(input)).toBeNull();
    },
  );
});

describe('normalizeUserCode', () => {
  it('normalizes case, spaces and the dash', () => {
    expect(normalizeUserCode('k7qm 2xpd')).toBe('K7QM-2XPD');
    expect(normalizeUserCode('K7QM-2XPD')).toBe('K7QM-2XPD');
  });

  it('rejects ambiguous characters and wrong lengths', () => {
    expect(normalizeUserCode('K7QM-2XP0')).toBeNull(); // 0 is not in the alphabet
    expect(normalizeUserCode('K7QM-2XPDD')).toBeNull();
    expect(normalizeUserCode('')).toBeNull();
  });
});

describe('linkFromArgv', () => {
  it('finds the link Windows passes to a second instance', () => {
    expect(linkFromArgv(['C:\\agent.exe', '--flag', 'kukuxsign://job/x'])).toBe('kukuxsign://job/x');
    expect(linkFromArgv(['C:\\agent.exe'])).toBeNull();
  });
});
