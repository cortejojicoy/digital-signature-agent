// Self-update for free macOS builds (no Developer ID).
//
// Squirrel.Mac (electron-updater) only installs updates for Developer ID
// signed apps, so a free build updates itself the way install.sh installs
// it: download the release's .zip, check its SHA-512 against latest-mac.yml,
// unzip it, check the bundle id, version and code signature, then, once the
// agent has quit, swap the app bundle and start the new one.
//
// Kept free of Electron imports so it can be tested.
import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, createWriteStream, promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import type { FetchLike } from './api';

export const APP_NAME = 'Kukux Sign Agent';
export const BUNDLE_ID = 'com.kukux.signagent';
const LSREGISTER =
  '/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister';

export interface MacAsset {
  file: string;
  sha512: string;
  size: number;
}

/** electron-builder's latest-mac.yml: the version, and the .zip for this CPU. */
export function parseLatestMac(yml: string, arch: string): { version: string; asset: MacAsset } {
  const version = /^version:\s*['"]?([^'"\s]+)/m.exec(yml)?.[1] ?? '';
  const assets: MacAsset[] = [];
  let current: Partial<MacAsset> | null = null;
  for (const line of yml.split(/\r?\n/)) {
    const url = /^\s*-\s*url:\s*['"]?([^'"\s]+)/.exec(line);
    if (url) {
      current = { file: url[1] };
      assets.push(current as MacAsset);
      continue;
    }
    if (!current || !/^\s{2,}\S/.test(line)) continue;
    const sha = /^\s+sha512:\s*['"]?([^'"\s]+)/.exec(line);
    const size = /^\s+size:\s*(\d+)/.exec(line);
    if (sha) current.sha512 = sha[1];
    if (size) current.size = Number(size[1]);
  }
  const asset = assets.find((a) => a.file.endsWith(`-mac-${arch}.zip`) && a.sha512);
  if (!version || !asset) throw new Error(`The release has no macOS ${arch} download.`);
  // A bare file name only: never a path or URL that could point elsewhere.
  if (!/^[\w.-]+\.zip$/.test(asset.file)) throw new Error('The release metadata names an unexpected file.');
  return { version, asset: { file: asset.file, sha512: asset.sha512, size: asset.size ?? 0 } };
}

/**
 * The .app bundle the agent runs from, or null when it can't be replaced in
 * place: not inside a bundle, or run from App Translocation (a quarantined
 * app opened where it was downloaded).
 */
export function bundlePath(exePath: string): string | null {
  const match = /^(.*\.app)\/Contents\/MacOS\/[^/]+$/.exec(exePath);
  if (!match || match[1].includes('/AppTranslocation/')) return null;
  return match[1];
}

/** True when this user can replace the bundle (its folder must be writable to swap it). */
export async function canReplace(bundle: string): Promise<boolean> {
  try {
    await fs.access(path.dirname(bundle), constants.W_OK);
    await fs.access(bundle, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

export type ExecFn = (file: string, args: string[]) => Promise<string>;

const execFileAsync = promisify(execFile);
const defaultExec: ExecFn = async (file, args) => (await execFileAsync(file, args)).stdout;

export interface PreparedUpdate {
  version: string;
  /** The verified, unzipped app, ready to move into place. */
  app: string;
  /** Holds the download and the unzipped app; removed after the swap. */
  dir: string;
}

export interface PrepareOptions {
  fetch: FetchLike;
  /** The release's download directory, e.g. https://github.com/<repo>/releases/download/v1.2.0 */
  baseUrl: string;
  version: string;
  arch?: string;
  onProgress?: (percent: number) => void;
  exec?: ExecFn;
  tmpRoot?: string;
}

/** Downloads and checks an update. Everything is left in a temp folder; nothing is installed yet. */
export async function prepareUpdate(o: PrepareOptions): Promise<PreparedUpdate> {
  const exec = o.exec ?? defaultExec;
  const arch = o.arch ?? process.arch;
  const base = o.baseUrl.replace(/\/+$/, '');
  if (!/^https:\/\//.test(base) && !/^http:\/\/(?:localhost|127\.0\.0\.1)[:/]/.test(base)) {
    throw new Error('Updates download over HTTPS only.');
  }

  const meta = await o.fetch(`${base}/latest-mac.yml`, { signal: AbortSignal.timeout(30_000) });
  if (!meta.ok) throw new Error(`Couldn't read the release (HTTP ${meta.status}).`);
  const { version, asset } = parseLatestMac(await meta.text(), arch);
  if (version !== o.version) throw new Error(`Expected version ${o.version}, but the release is ${version}.`);

  const dir = await fs.mkdtemp(path.join(o.tmpRoot ?? os.tmpdir(), 'kukux-update-'));
  try {
    const zip = path.join(dir, asset.file);
    await download(o.fetch, `${base}/${asset.file}`, zip, asset, o.onProgress);

    const out = path.join(dir, 'app');
    await fs.mkdir(out);
    await exec('/usr/bin/ditto', ['-x', '-k', zip, out]);
    const app = path.join(out, `${APP_NAME}.app`);
    await verifyApp(app, version, exec);
    await fs.rm(zip, { force: true });
    return { version, app, dir };
  } catch (err) {
    await fs.rm(dir, { recursive: true, force: true });
    throw err;
  }
}

async function download(fetchImpl: FetchLike, url: string, to: string, asset: MacAsset, onProgress?: (p: number) => void) {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(30 * 60_000) });
  if (!response.ok || !response.body) throw new Error(`Download failed (HTTP ${response.status}).`);
  const total = Number(response.headers.get('content-length')) || asset.size;
  const hash = createHash('sha512');
  const file = createWriteStream(to);
  let received = 0;
  let reported = -1;
  try {
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      hash.update(chunk);
      received += chunk.length;
      if (!file.write(chunk)) await new Promise((resolve) => file.once('drain', resolve));
      const percent = total > 0 ? Math.min(99, Math.floor((received / total) * 100)) : 0;
      if (percent !== reported) onProgress?.((reported = percent));
    }
  } finally {
    await new Promise<void>((resolve, reject) => file.end((err?: Error | null) => (err ? reject(err) : resolve())));
  }
  if (hash.digest('base64') !== asset.sha512) {
    throw new Error('The download is corrupt or was tampered with (SHA-512 mismatch).');
  }
  onProgress?.(100);
}

/** Same checks as install.sh: bundle id, version, and an intact code signature (ad-hoc for free builds). */
async function verifyApp(app: string, version: string, exec: ExecFn): Promise<void> {
  const plist = path.join(app, 'Contents', 'Info.plist');
  const read = async (key: string) =>
    (await exec('/usr/libexec/PlistBuddy', ['-c', `Print ${key}`, plist]).catch(() => '')).trim();
  const id = await read('CFBundleIdentifier');
  if (id !== BUNDLE_ID) throw new Error(`The download isn't ${APP_NAME} (bundle id "${id || 'missing'}").`);
  const got = await read('CFBundleShortVersionString');
  if (got !== version) throw new Error(`The download is version ${got || '?'}, expected ${version}.`);
  await exec('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]).catch(() => {
    throw new Error("The update's code signature is broken (damaged or modified download).");
  });
}

/**
 * Waits for the agent (PID) to exit, then swaps the bundle. On any failure it
 * puts the old app back. Optionally re-registers kukuxsign:// links and
 * starts the new app.
 */
export const SWAP_SCRIPT = `#!/bin/sh
# Kukux Sign Agent self-update: swap the app bundle once the agent has quit.
pid="$1" dest="$2" new="$3" dir="$4" register="$5" relaunch="$6" lsregister="$7"
i=0
while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 300 ]; do sleep 0.2; i=$((i + 1)); done
if kill -0 "$pid" 2>/dev/null; then exit 1; fi
rm -rf "$dest.old"
if mv "$dest" "$dest.old" && /usr/bin/ditto "$new" "$dest"; then
  rm -rf "$dest.old"
else
  rm -rf "$dest"
  mv "$dest.old" "$dest"
fi
xattr -dr com.apple.quarantine "$dest" 2>/dev/null || true
if [ "$register" = 1 ] && [ -x "$lsregister" ]; then "$lsregister" -f "$dest" >/dev/null 2>&1 || true; fi
rm -rf "$dir"
if [ "$relaunch" = 1 ]; then /usr/bin/open "$dest"; fi
`;

export interface InstallOptions {
  /** The running agent; the swap waits for it to exit. */
  pid: number;
  relaunch: boolean;
  /** Re-register kukuxsign:// with LaunchServices (off in tests). */
  register?: boolean;
}

/** Starts the swap in a detached shell that outlives the agent. Quit the agent right after. */
export async function installPrepared(update: PreparedUpdate, dest: string, o: InstallOptions): Promise<void> {
  const script = path.join(update.dir, 'swap.sh');
  await fs.writeFile(script, SWAP_SCRIPT, { mode: 0o700 });
  const child = spawn(
    '/bin/sh',
    [script, String(o.pid), dest, update.app, update.dir, o.register === false ? '0' : '1', o.relaunch ? '1' : '0', LSREGISTER],
    { detached: true, stdio: 'ignore' },
  );
  child.unref();
}
