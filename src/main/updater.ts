// Signed auto-updates (desktop-agent-plan.md §11). electron-updater verifies
// the update's code signature before installing (Authenticode publisher on
// Windows, the Developer ID signature via Squirrel on macOS).
import { app } from 'electron';
import { autoUpdater } from 'electron-updater';

const SIX_HOURS = 6 * 60 * 60 * 1000;
let started = false;

export function startUpdater(): void {
  if (!app.isPackaged || started) return;
  started = true;
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  void checkForUpdates();
  setInterval(() => void checkForUpdates(), SIX_HOURS).unref();
}

/** Called when a server refuses this agent as too old (HTTP 426). */
export async function checkForUpdates(): Promise<void> {
  if (!app.isPackaged) return;
  try {
    await autoUpdater.checkForUpdatesAndNotify();
  } catch {
    // Offline or feed unavailable: try again on the next interval.
  }
}
