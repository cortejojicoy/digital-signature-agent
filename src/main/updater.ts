// Auto-updates (desktop-agent-plan.md §11).
//
// Signed builds: electron-updater downloads and installs in the background and
// verifies the update's code signature first (Developer ID via Squirrel on
// macOS, the Authenticode publisher on Windows).
//
// Free (unsigned) builds: macOS refuses to let an unsigned app replace itself,
// so the agent only announces the update and opens the release page, where
// the one-line installer is. Windows still updates in place, verified by the
// SHA-512 in latest.yml over HTTPS.
import { app, Notification, shell } from 'electron';
import { autoUpdater } from 'electron-updater';

import { SIGNED_BUILD } from './build-info';

const SIX_HOURS = 6 * 60 * 60 * 1000;
const RELEASES_URL = 'https://github.com/cortejojicoy/digital-signature-agent/releases/latest';
let started = false;
let announced: string | null = null;

export function startUpdater(): void {
  if (!app.isPackaged || started) return;
  started = true;

  const manualOnly = process.platform === 'darwin' && !SIGNED_BUILD;
  autoUpdater.autoDownload = !manualOnly;
  autoUpdater.autoInstallOnAppQuit = !manualOnly;
  if (manualOnly) {
    autoUpdater.on('update-available', (info) => {
      if (announced === info.version || !Notification.isSupported()) return;
      announced = info.version;
      const n = new Notification({
        title: `Kukux Sign Agent ${info.version} is available`,
        body: 'Click to open the download page, then re-run the installer.',
      });
      n.on('click', () => void shell.openExternal(RELEASES_URL));
      n.show();
    });
  }

  void checkForUpdates();
  setInterval(() => void checkForUpdates(), SIX_HOURS).unref();
}

/** Called when a server refuses this agent as too old (HTTP 426). */
export async function checkForUpdates(): Promise<void> {
  if (!app.isPackaged) return;
  try {
    if (autoUpdater.autoDownload) await autoUpdater.checkForUpdatesAndNotify();
    else await autoUpdater.checkForUpdates();
  } catch {
    // Offline or feed unavailable: try again on the next interval.
  }
}
