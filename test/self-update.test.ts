// Self-update for free macOS builds. The parsing tests run anywhere; the
// end-to-end ones build a real ad-hoc signed app and need macOS tools
// (ditto, codesign, PlistBuddy).
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { FetchLike } from '../src/main/api';
import { APP_NAME, BUNDLE_ID, bundlePath, installPrepared, parseLatestMac, prepareUpdate } from '../src/main/self-update';

const LATEST_MAC = `version: 0.3.0
files:
  - url: kukux-sign-agent-0.3.0-mac-x64.zip
    sha512: X64SHA==
    size: 117674680
  - url: kukux-sign-agent-0.3.0-mac-arm64.zip
    sha512: ARMSHA==
    size: 109892049
  - url: kukux-sign-agent-0.3.0-mac-arm64.dmg
    sha512: DMGSHA==
    size: 109809860
path: kukux-sign-agent-0.3.0-mac-x64.zip
sha512: X64SHA==
releaseDate: '2026-10-02T03:12:19.844Z'
`;

describe('parseLatestMac', () => {
  it('picks the .zip for this CPU', () => {
    expect(parseLatestMac(LATEST_MAC, 'arm64')).toEqual({
      version: '0.3.0',
      asset: { file: 'kukux-sign-agent-0.3.0-mac-arm64.zip', sha512: 'ARMSHA==', size: 109892049 },
    });
    expect(parseLatestMac(LATEST_MAC, 'x64').asset.sha512).toBe('X64SHA==');
  });

  it('refuses a release without this CPU, or a file name that is a path', () => {
    expect(() => parseLatestMac(LATEST_MAC, 'ppc')).toThrow(/no macOS ppc download/);
    const sneaky = LATEST_MAC.replace('kukux-sign-agent-0.3.0-mac-arm64.zip', '../evil-mac-arm64.zip');
    expect(() => parseLatestMac(sneaky, 'arm64')).toThrow(/unexpected file/);
  });
});

describe('bundlePath', () => {
  it('finds the .app the agent runs from', () => {
    expect(bundlePath(`/Applications/${APP_NAME}.app/Contents/MacOS/${APP_NAME}`)).toBe(`/Applications/${APP_NAME}.app`);
  });

  it('refuses translocated apps and non-bundles', () => {
    expect(bundlePath(`/private/var/folders/x/AppTranslocation/ABC/d/${APP_NAME}.app/Contents/MacOS/${APP_NAME}`)).toBeNull();
    expect(bundlePath('/usr/local/bin/node')).toBeNull();
  });
});

const MAC = process.platform === 'darwin';

describe.skipIf(!MAC)('updating a free macOS build end to end', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'self-update-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  /** A minimal ad-hoc signed app, zipped like electron-builder does, plus its latest-mac.yml. */
  async function release(opts: { version?: string; bundleId?: string; tamper?: boolean; yamlVersion?: string; badSha?: boolean } = {}) {
    const version = opts.version ?? '9.9.9';
    const src = path.join(dir, 'build', version);
    const app = path.join(src, `${APP_NAME}.app`);
    await mkdir(path.join(app, 'Contents', 'MacOS'), { recursive: true });
    await writeFile(
      path.join(app, 'Contents', 'Info.plist'),
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${opts.bundleId ?? BUNDLE_ID}</string>
<key>CFBundleShortVersionString</key><string>${version}</string>
<key>CFBundleExecutable</key><string>${APP_NAME}</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>`,
    );
    const exe = path.join(app, 'Contents', 'MacOS', APP_NAME);
    await writeFile(exe, '#!/bin/sh\necho new\n', { mode: 0o755 });
    execFileSync('/usr/bin/codesign', ['--force', '--deep', '-s', '-', app]);
    if (opts.tamper) await writeFile(exe, '#!/bin/sh\necho tampered\n', { mode: 0o755 });

    const file = `kukux-sign-agent-${version}-mac-${process.arch}.zip`;
    const zip = path.join(dir, file);
    execFileSync('/usr/bin/ditto', ['-c', '-k', '--keepParent', app, zip]);
    const bytes = await readFile(zip);
    const sha = opts.badSha ? 'AAAA' : createHash('sha512').update(bytes).digest('base64');
    const yml = `version: ${opts.yamlVersion ?? version}\nfiles:\n  - url: ${file}\n    sha512: ${sha}\n    size: ${bytes.length}\n`;

    const urls: string[] = [];
    const fetch: FetchLike = async (url) => {
      urls.push(url);
      if (url.endsWith('/latest-mac.yml')) return new Response(yml);
      if (url.endsWith(`/${file}`)) return new Response(bytes, { headers: { 'content-length': String(bytes.length) } });
      return new Response('not found', { status: 404 });
    };
    return { fetch, urls, version };
  }

  const prepare = (r: { fetch: FetchLike; version: string }, progress?: number[]) =>
    prepareUpdate({
      fetch: r.fetch,
      baseUrl: `https://github.com/x/y/releases/download/v${r.version}`,
      version: r.version,
      tmpRoot: dir,
      onProgress: (p) => progress?.push(p),
    });

  it('downloads, verifies and unpacks the update', async () => {
    const r = await release();
    const progress: number[] = [];
    const update = await prepare(r, progress);

    expect(update.version).toBe('9.9.9');
    expect(existsSync(path.join(update.app, 'Contents', 'MacOS', APP_NAME))).toBe(true);
    expect(r.urls).toEqual([
      'https://github.com/x/y/releases/download/v9.9.9/latest-mac.yml',
      `https://github.com/x/y/releases/download/v9.9.9/kukux-sign-agent-9.9.9-mac-${process.arch}.zip`,
    ]);
    expect(progress.at(-1)).toBe(100);
  });

  it.each([
    ['a corrupted download', { badSha: true }, /SHA-512 mismatch/],
    ['another app', { bundleId: 'com.evil.app' }, /bundle id "com.evil.app"/],
    ['a modified app', { tamper: true }, /code signature is broken/],
    ['the wrong version', { yamlVersion: '9.9.8' }, /Expected version 9.9.9/],
  ])('refuses %s and leaves nothing behind', async (_name, opts, error) => {
    const r = await release(opts);
    await expect(prepare(r)).rejects.toThrow(error);
    expect((await readdir(dir)).filter((f) => f.startsWith('kukux-update-'))).toEqual([]);
  });

  it('swaps the bundle once the agent has quit, and cleans up', async () => {
    const r = await release();
    const update = await prepare(r);

    // The installed app: the old version.
    const dest = path.join(dir, 'Applications', `${APP_NAME}.app`);
    await mkdir(path.join(dest, 'Contents'), { recursive: true });
    await writeFile(path.join(dest, 'Contents', 'old-marker'), 'old');

    // Stands in for the running agent: the swap waits for it to exit.
    const agent = spawn('/bin/sleep', ['0.5']);
    await installPrepared(update, dest, { pid: agent.pid!, relaunch: false, register: false });
    expect(existsSync(path.join(dest, 'Contents', 'old-marker'))).toBe(true);

    await waitFor(() => !existsSync(update.dir));
    expect(existsSync(path.join(dest, 'Contents', 'old-marker'))).toBe(false);
    expect(await readFile(path.join(dest, 'Contents', 'MacOS', APP_NAME), 'utf8')).toContain('echo new');
    expect(existsSync(`${dest}.old`)).toBe(false);
    execFileSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', dest]);
  });
});

async function waitFor(check: () => boolean, timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > timeoutMs) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 50));
  }
}
