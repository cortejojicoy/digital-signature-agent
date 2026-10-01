// Latest release from GitHub, for the "Check for updates" view. Kept free of
// Electron imports so it can be unit tested.
import type { FetchLike } from './api';

export const REPO = 'cortejojicoy/digital-signature-agent';
export const RELEASES_API = `https://api.github.com/repos/${REPO}/releases/latest`;
export const RELEASES_PAGE = `https://github.com/${REPO}/releases/latest`;

export interface ReleaseInfo {
  version: string;
  name: string;
  notes: string;
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
