// App lifecycle, single-instance lock, protocol links, tray and windows
// (desktop-agent-plan.md §7).
import path from 'node:path';

import {
  app,
  BrowserWindow,
  ipcMain,
  Menu,
  nativeImage,
  Notification,
  safeStorage,
  session,
  Tray,
  type IpcMainInvokeEvent,
} from 'electron';

import {
  IPC,
  type JobState,
  type JobView,
  type PairingProgressView,
  type PairingResult,
  type StatusView,
} from '../shared/ipc';
import { Agent } from './agent';
import { APP_ORIGIN, appUrl, handleAppScheme, registerAppScheme } from './app-protocol';
import type { ConfirmRequest, JobOutcome } from './jobs';
import { loadNativeKeyStore } from './keystore';
import type { PairingProgress } from './pairing';
import { SCHEME, linkFromArgv } from './protocol';
import { Store } from './store';
import { checkForUpdates, startUpdater } from './updater';

const APP_ROOT = path.join(__dirname, '..', '..');
const RENDERER_DIR = path.join(APP_ROOT, 'dist', 'renderer');
const PRELOAD = path.join(APP_ROOT, 'dist', 'preload', 'index.js');
const DEV = !app.isPackaged;

// ── Single instance + protocol registration (§7.2) ──

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  if (process.defaultApp && process.argv.length >= 2) {
    app.setAsDefaultProtocolClient(SCHEME, process.execPath, [path.resolve(process.argv[1])]);
  } else {
    app.setAsDefaultProtocolClient(SCHEME);
  }
  app.enableSandbox();
  registerAppScheme();
  main();
}

function main(): void {
  const pendingLinks: string[] = [];
  let agent: Agent | null = null;
  let tray: Tray | null = null;
  let mainWindow: BrowserWindow | null = null;
  let pairingAbort: AbortController | null = null;

  interface PendingConfirm {
    request: ConfirmRequest;
    window: BrowserWindow;
    resolve: (approved: boolean) => void;
    decided: boolean;
  }
  const confirms = new Map<string, PendingConfirm>();
  let activeConfirm: PendingConfirm | null = null;

  const deliver = (raw: string) => {
    if (agent) void agent.handleLink(raw);
    else pendingLinks.push(raw);
  };

  // macOS delivers links via open-url, possibly before `ready`.
  app.on('open-url', (event, url) => {
    event.preventDefault();
    deliver(url);
  });
  // Windows delivers links in the argv of a second launch.
  app.on('second-instance', (_event, argv) => {
    const link = linkFromArgv(argv);
    if (link) deliver(link);
    else showMainWindow();
  });

  app.on('window-all-closed', () => {
    // Tray app: keep running with no windows.
  });

  // ── Hardening (§7.1) ──

  app.on('web-contents-created', (_event, contents) => {
    contents.on('will-navigate', (e) => e.preventDefault());
    contents.on('will-redirect', (e) => e.preventDefault());
    contents.on('will-attach-webview', (e) => e.preventDefault());
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  });

  app.whenReady().then(async () => {
    handleAppScheme(RENDERER_DIR);
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    session.defaultSession.setDevicePermissionHandler(() => false);
    if (process.platform === 'darwin') app.dock?.hide();

    const store = new Store(app.getPath('userData'), {
      isAvailable: () => safeStorage.isEncryptionAvailable(),
      encrypt: (plain) => safeStorage.encryptString(plain),
      decrypt: (cipher) => safeStorage.decryptString(cipher),
    });
    await store.load();

    agent = new Agent({
      keystore: loadNativeKeyStore(APP_ROOT),
      store,
      agentVersion: app.getVersion(),
      allowInsecureLocalhost: DEV,
      biometryOnly: process.env.KUKUX_BIOMETRY_ONLY === '1',
      confirm: openConfirm,
      parentWindow: () => activeConfirm?.window.getNativeWindowHandle(),
      onPairLink: (link) => {
        const win = showMainWindow();
        const send = () => win.webContents.send(IPC.pairPrefill, { origin: link.origin, code: link.code });
        if (win.webContents.isLoading()) win.webContents.once('did-finish-load', send);
        else send();
      },
      onJobOutcome: handleOutcome,
      onServersChanged: broadcastStatus,
    });

    registerIpc();
    createTray();
    startUpdater();

    const initial = linkFromArgv(process.argv);
    if (initial) pendingLinks.push(initial);
    for (const link of pendingLinks.splice(0)) void agent.handleLink(link);
    if (store.list().length === 0) showMainWindow();
  });

  // ── Windows ──

  function secureWebPreferences(): Electron.WebPreferences {
    return {
      preload: PRELOAD,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
      devTools: DEV,
    };
  }

  function showMainWindow(): BrowserWindow {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.show();
      mainWindow.focus();
      return mainWindow;
    }
    mainWindow = new BrowserWindow({
      width: 460,
      height: 620,
      resizable: false,
      maximizable: false,
      fullscreenable: false,
      title: 'Kukux Sign Agent',
      show: false,
      webPreferences: secureWebPreferences(),
    });
    mainWindow.removeMenu();
    void mainWindow.loadURL(appUrl('/status'));
    mainWindow.once('ready-to-show', () => mainWindow?.show());
    mainWindow.on('closed', () => {
      mainWindow = null;
      pairingAbort?.abort();
    });
    return mainWindow;
  }

  function openConfirm(request: ConfirmRequest): Promise<boolean> {
    return new Promise((resolve) => {
      const window = new BrowserWindow({
        width: 460,
        height: 520,
        resizable: false,
        minimizable: false,
        maximizable: false,
        fullscreenable: false,
        alwaysOnTop: true,
        title: 'Confirm signing',
        show: false,
        webPreferences: secureWebPreferences(),
      });
      window.removeMenu();
      const pending: PendingConfirm = { request, window, resolve, decided: false };
      confirms.set(request.job.uuid, pending);

      const expiresIn = Date.parse(request.job.expires_at) - Date.now();
      const timer = setTimeout(() => decide(request.job.uuid, false), Number.isFinite(expiresIn) ? Math.max(expiresIn, 0) : 300_000);

      window.on('closed', () => {
        clearTimeout(timer);
        decide(request.job.uuid, false);
        confirms.delete(request.job.uuid);
        if (activeConfirm === pending) activeConfirm = null;
      });
      void window.loadURL(appUrl(`/confirm/${request.job.uuid}`));
      window.once('ready-to-show', () => {
        window.show();
        window.focus();
        app.focus();
      });
    });
  }

  function decide(jobId: string, approved: boolean): void {
    const pending = confirms.get(jobId);
    if (!pending || pending.decided) return;
    pending.decided = true;
    if (approved) {
      // Keep the window open as the parent of the Touch ID / Hello prompt.
      activeConfirm = pending;
      sendJobState(jobId, { state: 'waiting_for_os_prompt' });
    } else if (!pending.window.isDestroyed()) {
      pending.window.close();
    }
    pending.resolve(approved);
  }

  function sendJobState(jobId: string, state: JobState): void {
    const pending = confirms.get(jobId);
    if (pending && !pending.window.isDestroyed()) pending.window.webContents.send(IPC.jobState, { id: jobId, ...state });
  }

  function handleOutcome(outcome: JobOutcome): void {
    if (outcome.result === 'ignored') return;
    const jobId = outcome.jobId;
    if (outcome.result === 'completed') sendJobState(jobId, { state: 'completed' });
    if (outcome.result === 'rejected') sendJobState(jobId, { state: 'rejected', reason: outcome.reason });
    if (outcome.result === 'failed') {
      sendJobState(jobId, { state: 'failed', error: outcome.error });
      if (outcome.code === 'agent_outdated') {
        notify('Update required', 'The server needs a newer version of Kukux Sign Agent. Updating…');
        void checkForUpdates();
      } else if (!confirms.has(jobId)) {
        notify('Signing failed', outcome.error);
      }
    }
    const pending = confirms.get(jobId);
    if (pending && !pending.window.isDestroyed()) setTimeout(() => pending.window.isDestroyed() || pending.window.close(), 2500);
  }

  function notify(title: string, body: string): void {
    if (Notification.isSupported()) new Notification({ title, body }).show();
  }

  function createTray(): void {
    const icon = nativeImage.createFromPath(path.join(APP_ROOT, 'build', 'tray', 'trayTemplate.png'));
    icon.setTemplateImage(true);
    tray = new Tray(icon);
    tray.setToolTip('Kukux Sign Agent');
    const rebuild = () => {
      tray?.setContextMenu(
        Menu.buildFromTemplate([
          { label: 'Open Kukux Sign Agent', click: () => showMainWindow() },
          { type: 'separator' },
          {
            label: 'Start at login',
            type: 'checkbox',
            checked: app.getLoginItemSettings().openAtLogin,
            click: (item) => {
              app.setLoginItemSettings({ openAtLogin: item.checked });
              rebuild();
            },
          },
          { type: 'separator' },
          { label: 'Quit', role: 'quit' },
        ]),
      );
    };
    rebuild();
    if (process.platform === 'win32') tray.on('click', () => showMainWindow());
  }

  function broadcastStatus(): void {
    for (const win of BrowserWindow.getAllWindows()) win.webContents.send(IPC.statusChanged);
  }

  // ── IPC (§7.1): only from our own bundled pages ──

  function trusted(event: IpcMainInvokeEvent): boolean {
    const url = event.senderFrame?.url ?? '';
    return url.startsWith(`${APP_ORIGIN}/index.html`);
  }

  function handle<A extends unknown[], R>(channel: string, fn: (...args: A) => Promise<R> | R): void {
    ipcMain.handle(channel, (event, ...args) => {
      if (!trusted(event)) throw new Error('untrusted sender');
      return fn(...(args as A));
    });
  }

  function registerIpc(): void {
    handle(IPC.getStatus, async (): Promise<StatusView> => ({
      version: app.getVersion(),
      platform: process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'other',
      capabilities: await agent!.capabilities(),
      servers: agent!.servers(),
    }));

    handle(IPC.startPairing, async (input: { origin: string; code: string }): Promise<PairingResult> => {
      pairingAbort?.abort();
      const abort = new AbortController();
      pairingAbort = abort;
      try {
        const server = await agent!.pair(input.origin, input.code, {
          signal: abort.signal,
          onProgress: (p) => mainWindow?.webContents.send(IPC.pairingProgress, toProgressView(p)),
        });
        return { ok: true, serverName: server.name };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      } finally {
        if (pairingAbort === abort) pairingAbort = null;
      }
    });

    handle(IPC.cancelPairing, () => {
      pairingAbort?.abort();
    });

    handle(IPC.getJob, (id: string): JobView | null => {
      const pending = confirms.get(id);
      if (!pending) return null;
      const { job, server } = pending.request;
      return {
        id: job.uuid,
        serverName: server.name,
        origin: server.origin,
        documentTitle: job.document.title,
        signerName: job.signer.name,
        purpose: job.purpose,
        expiresAt: job.expires_at,
        protection: server.protection,
        userPresence: server.userPresence,
      };
    });

    handle(IPC.approveJob, (id: string) => decide(id, true));
    handle(IPC.rejectJob, (id: string) => decide(id, false));
    handle(IPC.unpair, (serverId: string) => agent!.unpair(serverId));
  }
}

function toProgressView(p: PairingProgress): PairingProgressView {
  return p.stage === 'paired' ? { stage: 'paired', serverName: p.server.name } : p;
}
