import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { FetchLike } from '../src/main/api';
import {
  compareVersions,
  fetchLatestRelease,
  highlights,
  parseChangelog,
  plainNotes,
  RELEASES_API,
  RELEASES_PAGE,
  whatsNew,
  type ReleaseInfo,
} from '../src/main/release';
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
      highlights: ['Faster pairing'],
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

describe("what's new", () => {
  it('takes only top-level bullets from release notes, as plain text', () => {
    const body = [
      "## What's new",
      '- Pair **several apps** on one computer',
      '  - nested detail, skipped',
      '* See [your devices](https://example.com)',
      '',
      'Install: see the [installation guide](https://example.com).',
    ].join('\n');
    expect(highlights(body)).toEqual(['Pair several apps on one computer', 'See your devices']);
  });

  it('ignores release notes with no bullets (install boilerplate only)', () => {
    expect(highlights('Install: see the guide.\n\n**Free build** (paid code signing)')).toEqual([]);
  });

  it('shortens long bullets at a word and caps the count', () => {
    const long = `- ${'word '.repeat(60)}`;
    const [line] = highlights(long);
    expect(line.length).toBeLessThanOrEqual(121);
    expect(line.endsWith('…')).toBe(true);
    expect(highlights(Array.from({ length: 10 }, (_, i) => `- item ${i}`).join('\n'))).toHaveLength(6);
  });

  it('parses the changelog the app ships', async () => {
    const entries = parseChangelog(await readFile(path.join(__dirname, '..', 'CHANGELOG.md'), 'utf8'));
    expect(entries[0].version).toBe('Unreleased');
    expect(entries.find((e) => e.version === '0.2.0')).toMatchObject({ date: '2026-10-01' });
    for (const entry of entries) expect(entry.highlights.length).toBeGreaterThan(0);
  });

  const changelog = parseChangelog(
    ['## Unreleased', '- next thing', '## 0.2.0 (2026-10-01)', '- two', '## 0.1.0 (2026-09-30)', '- one'].join('\n'),
  );
  const release = (version: string, notes: string[] = ['- shiny']): ReleaseInfo => ({
    version,
    name: version,
    notes: '',
    highlights: highlights(notes.join('\n')),
    url: RELEASES_PAGE,
    publishedAt: '2026-10-05T08:00:00Z',
  });

  it('marks the running version, newest first', () => {
    expect(whatsNew(changelog, '0.2.0', { dev: false })).toEqual([
      { version: '0.2.0', date: '2026-10-01', highlights: ['two'], tag: 'current' },
      { version: '0.1.0', date: '2026-09-30', highlights: ['one'], tag: null },
    ]);
  });

  it('puts an available update first', () => {
    const [first, second] = whatsNew(changelog, '0.2.0', { dev: false, update: release('0.3.0') });
    expect(first).toEqual({ version: '0.3.0', date: '2026-10-05', highlights: ['shiny'], tag: 'new' });
    expect(second.tag).toBe('current');
  });

  it('ignores an "update" that is not newer', () => {
    expect(whatsNew(changelog, '0.2.0', { dev: false, update: release('0.2.0') }).map((e) => e.tag)).toEqual(['current', null]);
  });

  it('shows Unreleased only in dev builds', () => {
    expect(whatsNew(changelog, '0.2.0', { dev: true })[0]).toMatchObject({ version: 'Unreleased', tag: 'unreleased' });
    expect(whatsNew(changelog, '0.2.0', { dev: false }).some((e) => e.version === 'Unreleased')).toBe(false);
  });
});
