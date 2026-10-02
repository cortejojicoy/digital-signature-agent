// Latest release from GitHub, for the "Check for updates" view. Kept free of
// Electron imports so it can be unit tested.
import type { WhatsNewEntry } from '../shared/ipc';
import type { FetchLike } from './api';

export const REPO = 'cortejojicoy/digital-signature-agent';
export const RELEASES_API = `https://api.github.com/repos/${REPO}/releases/latest`;
export const RELEASES_PAGE = `https://github.com/${REPO}/releases/latest`;
export const ALL_RELEASES_PAGE = `https://github.com/${REPO}/releases`;

export interface ReleaseInfo {
  version: string;
  name: string;
  notes: string;
  /** The release's top-level bullet points, for What's new. Empty when it has none. */
  highlights: string[];
  url: string;
  publishedAt: string;
}

export async function fetchLatestRelease(fetchImpl: FetchLike, timeoutMs = 15_000): Promise<ReleaseInfo> {
  const response = await fetchImpl(RELEASES_API, {
    headers: { Accept: 'application/vnd.github+json' },
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (response.status === 404) throw new Error('No releases published yet.');
  if (!response.ok) throw new Error(`GitHub returned HTTP ${response.status}.`);

  const data = (await response.json()) as Record<string, unknown>;
  const tag = typeof data.tag_name === 'string' ? data.tag_name : '';
  const version = tag.replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+/.test(version)) throw new Error('GitHub sent an invalid release.');

  // Only ever open this repository's own release pages.
  const htmlUrl = typeof data.html_url === 'string' ? data.html_url : '';
  const url = htmlUrl.startsWith(`https://github.com/${REPO}/releases/`) ? htmlUrl : RELEASES_PAGE;

  return {
    version,
    name: typeof data.name === 'string' && data.name.trim() ? data.name.trim() : tag,
    notes: plainNotes(typeof data.body === 'string' ? data.body : ''),
    highlights: highlights(typeof data.body === 'string' ? data.body : ''),
    url,
    publishedAt: typeof data.published_at === 'string' ? data.published_at : '',
  };
}

/** Markdown release notes as short plain text: links become their text. */
export function plainNotes(markdown: string, max = 600): string {
  const text = markdown
    .replace(/\r\n/g, '\n')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/^#+\s*/gm, '')
    .replace(/[*_`]/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return text.length > max ? `${text.slice(0, max).trimEnd()}…` : text;
}

/**
 * Top-level bullet points of Markdown notes, as short plain lines. Install
 * instructions and other prose are left out: only bullets count as changes.
 */
export function highlights(markdown: string, max = 6, maxLength = 120): string[] {
  const items: string[] = [];
  for (const line of markdown.replace(/\r\n/g, '\n').split('\n')) {
    const bullet = /^[-*+]\s+(.+)$/.exec(line); // top level only: nested bullets are indented
    if (!bullet) continue;
    const text = bullet[1]
      .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
      .replace(/[*_`]/g, '')
      .trim();
    if (!text) continue;
    items.push(text.length > maxLength ? `${text.slice(0, maxLength).replace(/\s+\S*$/, '')}…` : text);
    if (items.length === max) break;
  }
  return items;
}

export interface ChangelogEntry {
  /** "0.2.2", or "Unreleased". */
  version: string;
  /** YYYY-MM-DD, or "" when the heading has no date. */
  date: string;
  highlights: string[];
}

/** CHANGELOG.md: `## 0.2.2 (2026-10-01)` headings, each followed by bullets. Newest first, as written. */
export function parseChangelog(markdown: string): ChangelogEntry[] {
  const entries: ChangelogEntry[] = [];
  for (const section of markdown.replace(/\r\n/g, '\n').split(/^## /m).slice(1)) {
    const [heading, ...body] = section.split('\n');
    const match = /^v?(\d+\.\d+\.\d+|Unreleased)\b(?:.*?(\d{4}-\d{2}-\d{2}))?/i.exec(heading.trim());
    if (!match) continue;
    const version = /^unreleased$/i.test(match[1]) ? 'Unreleased' : match[1];
    entries.push({ version, date: match[2] ?? '', highlights: highlights(body.join('\n'), 8) });
  }
  return entries;
}

/**
 * What's new, newest first: an available update (from GitHub), then this
 * version and older ones (from the bundled changelog). `Unreleased` shows
 * only in dev builds, where it's what you're running.
 */
export function whatsNew(
  changelog: ChangelogEntry[],
  current: string,
  opts: { dev: boolean; update?: ReleaseInfo | null; limit?: number },
): WhatsNewEntry[] {
  const update = opts.update && compareVersions(opts.update.version, current) > 0 ? opts.update : null;
  const entries: WhatsNewEntry[] = [];
  if (update) {
    entries.push({ version: update.version, date: update.publishedAt.slice(0, 10), highlights: update.highlights, tag: 'new' });
  }
  for (const entry of changelog) {
    if (entry.version === 'Unreleased') {
      if (opts.dev && entry.highlights.length > 0) entries.push({ ...entry, tag: 'unreleased' });
      continue;
    }
    if (compareVersions(entry.version, current) > 0) continue; // the update entry above covers newer versions
    entries.push({ ...entry, tag: entry.version === current ? 'current' : null });
  }
  return entries.slice(0, opts.limit ?? 5);
}

/** Compares x.y.z versions numerically; pre-release suffixes are ignored. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => v.replace(/^v/, '').split(/[-+]/)[0].split('.').map((n) => Number(n) || 0);
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const diff = (x[i] ?? 0) - (y[i] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  return 0;
}
