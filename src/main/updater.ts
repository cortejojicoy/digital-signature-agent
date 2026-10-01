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
// Free macOS builds and npm run dev: an unsigned app can't replace itself, so
// the agent opens the release page instead, where the one-line installer is.
import { app, net, Notification, shell } from 'electron';
import { autoUpdater } from 'electron-updater';

import type { UpdateView } from '../shared/ipc';
import { SIGNED_BUILD } from './build-info';
import { compareVersions, fetchLatestRelease, RELEASES_PAGE, type ReleaseInfo } from './release';

const SIX_HOURS = 6 * 60 * 60 * 1000;

let status: UpdateView = { state: 'idle' };
let listener: (status: UpdateView) => void = () => {};
let started = false;
let announced: string | null = null;

function canInstallInPlace(): boolean {
  return app.isPackaged && !(process.platform === 'darwin' && !SIGNED_BUILD);
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
  autoUpdater.autoInstallOnAppQuit = canInstallInPlace();
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

  if (!canInstallInPlace()) {
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
    autoUpdater.quitAndInstall();
  } else if (status.state === 'available') {
    if (status.install === 'open_page') await shell.openExternal(status.release.url);
    else await download(status.release);
  } else if (status.state === 'error') {
    await shell.openExternal(RELEASES_PAGE);
  }
}

async function download(release: ReleaseInfo): Promise<void> {
  set({ state: 'downloading', release, percent: 0 });
  try {
    // Loads latest*.yml from the release; the installer is verified against it.
    const result = await autoUpdater.checkForUpdates();
    if (!result?.isUpdateAvailable) throw new Error('The update files are not ready yet. Try again later.');
    await autoUpdater.downloadUpdate();
  } catch (err) {
    set({ state: 'error', message: `Download failed. ${message(err)}` });
  }
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
