// Updates (desktop-agent-plan.md §11).
//
// The latest version and its notes come from the GitHub Releases API, so the
// "Check for updates" view can say exactly what's new. Installing depends on
// the build:
//
// Signed builds and Windows: electron-updater downloads latest*.yml and the
// installer from the same release, verifies it (Developer ID via Squirrel on
// macOS; the Authenticode publisher, or the SHA-512 over HTTPS for unsigned
// Windows), and installs on restart.
//
// Free macOS builds: Squirrel.Mac only installs Developer ID signed updates,
// so the agent updates itself the way install.sh installs it (self-update.ts):
// download the .zip, check its SHA-512 and code signature, then swap the app
// bundle once it quits.
//
// npm run dev, or an app the user can't replace (a folder they can't write
// to): the agent opens the release page instead.
import { app, net, Notification, shell } from 'electron';
import { autoUpdater } from 'electron-updater';

import type { UpdateView } from '../shared/ipc';
import { SIGNED_BUILD } from './build-info';
import { compareVersions, fetchLatestRelease, RELEASE_DOWNLOADS, RELEASES_PAGE, type ReleaseInfo } from './release';
import { bundlePath, canReplace, installPrepared, prepareUpdate, type PreparedUpdate } from './self-update';

const SIX_HOURS = 6 * 60 * 60 * 1000;

let status: UpdateView = { state: 'idle' };
let listener: (status: UpdateView) => void = () => {};
let started = false;
let announced: string | null = null;
/** Free macOS builds: the downloaded, verified update waiting for a restart. */
let prepared: PreparedUpdate | null = null;
let swapping = false;

type Installer = 'electron-updater' | 'bundle-swap' | 'release-page';

/** How this copy of the agent can update. */
async function installer(): Promise<Installer> {
  if (!app.isPackaged) return 'release-page';
  if (process.platform !== 'darwin' || SIGNED_BUILD) return 'electron-updater';
  const bundle = bundlePath(app.getPath('exe'));
  return bundle && (await canReplace(bundle)) ? 'bundle-swap' : 'release-page';
}

function set(next: UpdateView): void {
  status = next;
  listener(status);
}

export function getUpdateStatus(): UpdateView {
  return status;
}

export function startUpdater(onChange: (status: UpdateView) => void): void {
  listener = onChange;
  if (started) return;
  started = true;

  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = app.isPackaged && (process.platform !== 'darwin' || SIGNED_BUILD);
  // Like autoInstallOnAppQuit: a downloaded free-build update installs when
  // the agent quits, without starting it again.
  // The swap is started asynchronously, so hold the quit until it's running.
  app.on('will-quit', (event) => {
    if (!prepared || swapping) return;
    event.preventDefault();
    void swap(false).finally(() => app.quit());
  });
  autoUpdater.on('download-progress', (p) => {
    if (status.state === 'downloading') set({ ...status, percent: Math.round(p.percent) });
  });
  autoUpdater.on('update-downloaded', () => {
    if (status.state !== 'downloading') return;
    set({ state: 'ready', release: status.release });
    if (Notification.isSupported()) {
      new Notification({ title: `Update ${status.release.version} ready`, body: 'Restart the agent to install it.' }).show();
    }
  });
  // download() reports failures; without a listener an 'error' event throws.
  autoUpdater.on('error', () => {});

  if (!app.isPackaged) return;
  void checkForUpdates({ background: true });
  setInterval(() => void checkForUpdates({ background: true }), SIX_HOURS).unref();
}

/**
 * Background checks (startup, every 6 h, a server's 426) download in place
 * when they can and stay quiet on errors. A manual check reports everything.
 */
export async function checkForUpdates(opts: { background?: boolean } = {}): Promise<void> {
  if (status.state === 'checking' || status.state === 'downloading' || status.state === 'ready') return;
  const previous = status;
  if (!opts.background) set({ state: 'checking' });

  let release: ReleaseInfo;
  try {
    release = await fetchLatestRelease((input, init) => net.fetch(input, init));
  } catch (err) {
    set(opts.background ? previous : { state: 'error', message: `Couldn't check for updates. ${message(err)}` });
    return;
  }

  if (compareVersions(release.version, app.getVersion()) <= 0) {
    set({ state: 'up_to_date', checkedAt: new Date().toISOString() });
    return;
  }

  if ((await installer()) === 'release-page') {
    set({ state: 'available', release, install: 'open_page' });
    if (opts.background) announce(release);
    return;
  }

  set({ state: 'available', release, install: 'download' });
  if (opts.background) await download(release);
}

/** The view's main update button: download, restart, or open the release page. */
export async function installUpdate(): Promise<void> {
  if (status.state === 'ready') {
    if (prepared) {
      await swap(true);
      app.quit();
    } else {
      autoUpdater.quitAndInstall();
    }
  } else if (status.state === 'available') {
    if (status.install === 'open_page') await shell.openExternal(status.release.url);
    else await download(status.release);
  } else if (status.state === 'error') {
    await shell.openExternal(RELEASES_PAGE);
  }
}

async function download(release: ReleaseInfo): Promise<void> {
  set({ state: 'downloading', release, percent: 0 });
  if ((await installer()) === 'bundle-swap') return downloadBundle(release);
  try {
    // Loads latest*.yml from the release; the installer is verified against it.
    const result = await autoUpdater.checkForUpdates();
    if (!result?.isUpdateAvailable) throw new Error('The update files are not ready yet. Try again later.');
    await autoUpdater.downloadUpdate();
  } catch (err) {
    set({ state: 'error', message: `Download failed. ${message(err)}` });
  }
}

async function downloadBundle(release: ReleaseInfo): Promise<void> {
  try {
    prepared = await prepareUpdate({
      fetch: (input, init) => net.fetch(input, init),
      baseUrl: `${RELEASE_DOWNLOADS}/v${release.version}`,
      version: release.version,
      onProgress: (percent) => {
        if (status.state === 'downloading') set({ ...status, percent });
      },
    });
  } catch (err) {
    set({ state: 'error', message: `Download failed. ${message(err)}` });
    return;
  }
  set({ state: 'ready', release });
  if (Notification.isSupported()) {
    new Notification({ title: `Update ${release.version} ready`, body: 'Restart the agent to install it.' }).show();
  }
}

/** Starts the bundle swap; it runs after the agent exits. */
async function swap(relaunch: boolean): Promise<void> {
  const bundle = bundlePath(app.getPath('exe'));
  if (!prepared || !bundle || swapping) return;
  swapping = true;
  await installPrepared(prepared, bundle, { pid: process.pid, relaunch });
}

function announce(release: ReleaseInfo): void {
  if (announced === release.version || !Notification.isSupported()) return;
  announced = release.version;
  const n = new Notification({
    title: `Update available: ${release.version}`,
    body: 'Click to download.',
  });
  n.on('click', () => void shell.openExternal(release.url));
  n.show();
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
