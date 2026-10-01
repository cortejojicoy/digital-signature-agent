import { describe, expect, it } from 'vitest';

import { isLocalNetworkHost, linkFromArgv, normalizeOrigin, normalizeUserCode, parseLink } from '../src/main/protocol';

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

  it('refuses plain-HTTP pair links unless the local network is allowed', () => {
    const raw = 'kukuxsign://pair?o=http%3A%2F%2F192.168.1.20%3A8000&c=K7QM-2XPD';
    expect(parseLink(raw)).toBeNull();
    expect(parseLink(raw, { allowInsecureLocalNetwork: true })).toMatchObject({ origin: 'http://192.168.1.20:8000' });
    expect(parseLink('kukuxsign://pair?o=http%3A%2F%2Fevil.example.com&c=K7QM-2XPD', { allowInsecureLocalNetwork: true })).toBeNull();
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

describe('normalizeOrigin with allowInsecureLocalNetwork', () => {
  const dev = { allowInsecureLocalNetwork: true };

  it.each([
    ['http://localhost:8000', 'http://localhost:8000'],
    ['http://127.0.0.1:8000', 'http://127.0.0.1:8000'],
    ['http://[::1]:8000', 'http://[::1]:8000'],
    ['http://192.168.1.20:8000', 'http://192.168.1.20:8000'],
    ['http://10.0.0.5', 'http://10.0.0.5'],
    ['http://172.20.1.2:8080', 'http://172.20.1.2:8080'],
    ['http://MacMini.local:8000', 'http://macmini.local:8000'],
    ['http://my-app.test', 'http://my-app.test'],
    ['http://app.localhost', 'http://app.localhost'],
  ])('accepts %s', (input, expected) => {
    expect(normalizeOrigin(input, dev)).toBe(expected);
    expect(normalizeOrigin(input)).toBeNull();
  });

  it.each(['http://sign.example.gov.ph', 'http://8.8.8.8', 'http://172.32.0.1', 'http://100.64.0.1', 'http://localhost.example.com'])(
    'still rejects %s',
    (input) => {
      expect(normalizeOrigin(input, dev)).toBeNull();
    },
  );
});

describe('isLocalNetworkHost', () => {
  it.each(['localhost', '127.0.0.1', '127.1.2.3', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '169.254.1.1', '[::1]', '[fd12:3456::1]', '[fe80::1]', 'a.local', 'a.b.test'])(
    'local: %s',
    (host) => {
      expect(isLocalNetworkHost(host)).toBe(true);
    },
  );

  it.each(['example.com', '8.8.8.8', '172.15.0.1', '172.32.0.1', '192.169.0.1', '[2001:db8::1]', '[fc::1]', '[fe7f::1]', 'local', 'test', 'evil.com.local.example.com'])(
    'not local: %s',
    (host) => {
      expect(isLocalNetworkHost(host)).toBe(false);
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
