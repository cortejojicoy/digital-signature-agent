import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { FetchLike } from '../src/main/api';
import { compareVersions, fetchLatestRelease, plainNotes, RELEASES_API, RELEASES_PAGE } from '../src/main/release';
import { SettingsStore } from '../src/main/settings';

function github(body: unknown, status = 200): { fetch: FetchLike; urls: string[] } {
  const urls: string[] = [];
  return {
    urls,
    fetch: async (url) => {
      urls.push(url);
      return new Response(JSON.stringify(body), { status });
    },
  };
}

describe('fetchLatestRelease', () => {
  it('reads the version, notes and page of the latest release', async () => {
    const { fetch, urls } = github({
      tag_name: 'v1.2.0',
      name: 'v1.2.0',
      body: '## Fixes\n- Faster **pairing**\n\nInstall: see [docs/installation.md](https://x/y).',
      html_url: 'https://github.com/cortejojicoy/digital-signature-agent/releases/tag/v1.2.0',
      published_at: '2026-09-30T08:00:00Z',
    });
    const release = await fetchLatestRelease(fetch);
    expect(urls).toEqual([RELEASES_API]);
    expect(release).toEqual({
      version: '1.2.0',
      name: 'v1.2.0',
      notes: 'Fixes\n- Faster pairing\n\nInstall: see docs/installation.md.',
      url: 'https://github.com/cortejojicoy/digital-signature-agent/releases/tag/v1.2.0',
      publishedAt: '2026-09-30T08:00:00Z',
    });
  });

  it('never links outside this repository', async () => {
    const { fetch } = github({ tag_name: 'v1.2.0', html_url: 'https://evil.example.com/download' });
    expect((await fetchLatestRelease(fetch)).url).toBe(RELEASES_PAGE);
  });

  it('reports missing or malformed releases', async () => {
    await expect(fetchLatestRelease(github({}, 404).fetch)).rejects.toThrow(/No releases/);
    await expect(fetchLatestRelease(github({}, 500).fetch)).rejects.toThrow(/HTTP 500/);
    await expect(fetchLatestRelease(github({ tag_name: 'nightly' }).fetch)).rejects.toThrow(/invalid release/);
  });
});

describe('compareVersions', () => {
  it.each([
    ['1.2.0', '1.1.9', 1],
    ['v1.10.0', '1.9.0', 1],
    ['1.0.0', '1.0.0', 0],
    ['1.0', '1.0.0', 0],
    ['0.1.0', '0.2.0', -1],
    ['1.0.0-beta.1', '1.0.0', 0],
  ])('%s vs %s', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
  });
});

describe('plainNotes', () => {
  it('truncates long notes', () => {
    expect(plainNotes('a'.repeat(700), 10)).toBe(`${'a'.repeat(10)}…`);
  });
});

describe('SettingsStore', () => {
  it('defaults Developer mode off and persists changes', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'settings-'));
    try {
      const settings = new SettingsStore(dir);
      expect(await settings.load()).toEqual({ developerMode: false });
      await settings.update({ developerMode: true });
      expect(JSON.parse(await readFile(path.join(dir, 'settings.json'), 'utf8'))).toEqual({ developerMode: true });
      expect(await new SettingsStore(dir).load()).toEqual({ developerMode: true });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
