// App lifecycle, single-instance lock, protocol links, tray and windows
// (desktop-agent-plan.md §7).
import path from 'node:path';

import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  net,
  Notification,
  safeStorage,
  screen,
  session,
  shell,
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
  type UpdateView,
} from '../shared/ipc';
import { Agent } from './agent';
import { APP_ORIGIN, appUrl, handleAppScheme, registerAppScheme } from './app-protocol';
import type { ConfirmRequest, JobOutcome } from './jobs';
import { loadNativeKeyStore, type Sealer } from './keystore';
import { PairingError, type PairingProgress } from './pairing';
import { SCHEME, linkFromArgv } from './protocol';
import { AVOID_KEYCHAIN } from './build-info';
import { SettingsStore } from './settings';
import { Store, sealedTokenCipher, type TokenCipher } from './store';
import { ALL_RELEASES_PAGE } from './release';
import { checkForUpdates, getUpdateStatus, installUpdate, startUpdater } from './updater';

const APP_ROOT = path.join(__dirname, '..', '..');
const RENDERER_DIR = path.join(APP_ROOT, 'dist', 'renderer');
const PRELOAD = path.join(APP_ROOT, 'dist', 'preload', 'index.js');
const DEV = !app.isPackaged;

// Windows are as tall as their content (the page reports it, see fitContent),
// within these bounds and the screen. The width stays fixed.
const WINDOW_WIDTH = 460;
const MIN_HEIGHT = 200;
const SCREEN_MARGIN = 48;

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
  // Free macOS builds: keep Chromium out of the login keychain (build-info.ts).
  if (AVOID_KEYCHAIN) app.commandLine.appendSwitch('use-mock-keychain');
  registerAppScheme();
  main();
}

function main(): void {
  const pendingLinks: string[] = [];
  let agent: Agent | null = null;
  let tray: Tray | null = null;
  let mainWindow: BrowserWindow | null = null;
  let pairingAbort: AbortController | null = null;
  // Resolves the "already paired here: re-pair?" question of the running pairing.
  let repairAnswer: ((repair: boolean) => void) | null = null;
  // The devices page from the last account_already_paired failure. The
  // renderer can only ask to open this one, never a URL of its own.
  let devicesPage: string | null = null;
  let settings: SettingsStore | null = null;
  // Developer mode: plain http:// to local-network apps. Always on under npm run dev.
  let developerMode = DEV;

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

    const keystore = loadNativeKeyStore(APP_ROOT, { keyDirectory: path.join(app.getPath('userData'), 'keys') });
    const store = new Store(app.getPath('userData'), tokenCipher(keystore));
    await store.load();
    settings = new SettingsStore(app.getPath('userData'));
    developerMode = DEV || (await settings.load()).developerMode;

    agent = new Agent({
      keystore,
      store,
      agentVersion: app.getVersion(),
      allowInsecureLocalNetwork: developerMode,
      // In Developer mode, requests go through Chromium's network stack, which
      // trusts the OS certificate store, so Herd / Valet / mkcert HTTPS works
      // for local testing. Otherwise Node's fetch and its bundled CA list.
      fetch: (input, init) => (developerMode ? net.fetch(input, init) : fetch(input, init)),
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
    // Device types for older pairings, and revokes left over from an offline unpair.
    void agent.init().catch(() => {});
    setInterval(() => void agent?.retryRevokes().catch(() => {}), 60 * 60_000);
    createTray();
    startUpdater(broadcastUpdate);

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
      width: WINDOW_WIDTH,
      height: 560,
      useContentSize: true,
      resizable: false,
      maximizable: false,
      fullscreenable: false,
      title: 'Kukux Sign Agent',
      show: false,
      webPreferences: secureWebPreferences(),
    });
    mainWindow.removeMenu();
    void mainWindow.loadURL(appUrl('/status'));
    showWhenFitted(mainWindow, (win) => win.show());
    mainWindow.on('closed', () => {
      mainWindow = null;
      pairingAbort?.abort();
    });
    return mainWindow;
  }

  function openConfirm(request: ConfirmRequest): Promise<boolean> {
    return new Promise((resolve) => {
      const window = new BrowserWindow({
        width: WINDOW_WIDTH,
        height: 420,
        useContentSize: true,
        resizable: false,
        minimizable: false,
        maximizable: false,
        fullscreenable: false,
        alwaysOnTop: true,
        title: request.job.purpose === 'login' ? 'Confirm sign-in' : 'Confirm signing',
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
      showWhenFitted(window, (win) => {
        win.show();
        win.focus();
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
        notify('Update required', 'This app needs a newer agent. Updating…');
        void checkForUpdates({ background: true });
      } else if (outcome.code === 'not_paired') {
        // A sign-in from an app this computer isn't paired with: offer pairing.
        notify('Not paired', outcome.error);
        showMainWindow();
      } else if (!confirms.has(jobId)) {
        notify('Signing failed', outcome.error);
      }
    }
    const pending = confirms.get(jobId);
    if (pending && !pending.window.isDestroyed()) setTimeout(() => pending.window.isDestroyed() || pending.window.close(), 2500);
  }

  // ── Content-sized windows ──

  const awaitingFit = new Map<number, () => void>();

  /** Shows a window once it has its content's height, so it doesn't visibly jump; or soon after load regardless. */
  function showWhenFitted(win: BrowserWindow, show: (win: BrowserWindow) => void): void {
    let shown = false;
    const reveal = () => {
      if (shown || win.isDestroyed()) return;
      shown = true;
      awaitingFit.delete(win.id);
      show(win);
    };
    awaitingFit.set(win.id, reveal);
    win.once('ready-to-show', () => setTimeout(reveal, 400));
    win.on('closed', () => awaitingFit.delete(win.id));
  }

  function fitContent(win: BrowserWindow, height: number): void {
    const { workArea } = screen.getDisplayMatching(win.getBounds());
    const target = Math.round(Math.min(Math.max(height, MIN_HEIGHT), workArea.height - SCREEN_MARGIN));
    const [width, current] = win.getContentSize();
    const firstFit = awaitingFit.get(win.id);
    if (Math.abs(current - target) >= 2) {
      // Animated on macOS once visible; instant before the first show.
      win.setContentSize(width, target, !firstFit);
      // Growing must not push the bottom off the screen.
      const bounds = win.getBounds();
      const overflow = bounds.y + bounds.height - (workArea.y + workArea.height);
      if (overflow > 0) win.setPosition(bounds.x, Math.max(workArea.y, bounds.y - overflow));
    }
    firstFit?.();
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
          { label: 'Open', click: () => showMainWindow() },
          {
            label: 'Check for updates',
            click: () => {
              showMainWindow();
              void checkForUpdates();
            },
          },
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

  function broadcastUpdate(update: UpdateView): void {
    for (const win of BrowserWindow.getAllWindows()) win.webContents.send(IPC.updateChanged, update);
  }

  /** Turning it on is confirmed here, in the main process, not by the page. */
  async function setDeveloperMode(on: boolean): Promise<void> {
    if (DEV || on === developerMode) return;
    if (on) {
      const options: Electron.MessageBoxOptions = {
        type: 'warning',
        message: 'Turn on Developer mode?',
        detail:
          'Allows pairing with apps on this computer or your local network over plain HTTP, for testing. ' +
          'Traffic to those apps is not encrypted.',
        buttons: ['Turn on', 'Cancel'],
        defaultId: 1,
        cancelId: 1,
      };
      const { response } = mainWindow ? await dialog.showMessageBox(mainWindow, options) : await dialog.showMessageBox(options);
      if (response !== 0) return;
    }
    developerMode = on;
    agent!.setAllowInsecureLocalNetwork(on);
    await settings!.update({ developerMode: on });
    broadcastStatus();
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
    handle(IPC.getStatus, async (): Promise<StatusView> => {
      // Other devices load in the background; the window refreshes when they arrive.
      void agent!
        .refreshOtherDevices()
        .then((changed) => changed && broadcastStatus())
        .catch(() => {});
      return {
        version: app.getVersion(),
        platform: process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'other',
        capabilities: await agent!.capabilities(),
        servers: agent!.servers(),
        pendingRevokes: agent!.pendingRevokes(),
        developerMode: { on: developerMode, locked: DEV },
      };
    });

    handle(IPC.startPairing, async (input: { origin: string; code: string }): Promise<PairingResult> => {
      pairingAbort?.abort();
      const abort = new AbortController();
      pairingAbort = abort;
      devicesPage = null;
      try {
        let rebound = false;
        const server = await agent!.pair(input.origin, input.code, {
          signal: abort.signal,
          onProgress: (p) => {
            if (p.stage === 'paired') rebound = p.rebound;
            mainWindow?.webContents.send(IPC.pairingProgress, toProgressView(p));
          },
          confirmRepair: () =>
            new Promise<boolean>((resolve) => {
              repairAnswer = resolve;
              abort.signal.addEventListener('abort', () => resolve(false), { once: true });
            }),
        });
        return { ok: true, serverName: server.name, rebound };
      } catch (err) {
        if (err instanceof PairingError) {
          const blocking = err.serverId ? agent!.servers().find((s) => s.id === err.serverId) : undefined;
          devicesPage = err.manageUrl ?? null;
          return {
            ok: false,
            error: err.message,
            code: err.code,
            serverId: err.serverId,
            serverName: blocking?.name,
            manageUrl: err.manageUrl,
          };
        }
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      } finally {
        repairAnswer = null;
        if (pairingAbort === abort) pairingAbort = null;
      }
    });

    handle(IPC.cancelPairing, () => {
      pairingAbort?.abort();
    });

    handle(IPC.confirmRepair, (repair: boolean) => {
      const answer = repairAnswer;
      repairAnswer = null;
      answer?.(repair === true);
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
        deviceType: server.deviceType ?? 'other',
        requestingApp: job.requesting_app?.name,
        // Only for their own purpose, so no other job can look like a sign-in.
        login:
          job.purpose === 'login' && job.login
            ? { matchCode: job.login.match_code, browser: job.login.browser ?? '', ip: job.login.ip ?? '' }
            : undefined,
        transfer: job.purpose === 'transfer' && job.transfer ? { name: job.transfer.name, device: job.transfer.device } : undefined,
      };
    });

    handle(IPC.approveJob, (id: string) => decide(id, true));
    handle(IPC.rejectJob, (id: string) => decide(id, false));
    handle(IPC.unpair, (serverId: string, opts?: { offline?: unknown }) =>
      agent!.unpair(String(serverId), { offline: opts?.offline === 'remove' ? 'remove' : 'ask' }),
    );
    handle(IPC.retryRevokes, (origin: string) => agent!.retryRevokes(String(origin)));
    handle(IPC.openDevicesPage, async () => {
      if (devicesPage) await shell.openExternal(devicesPage);
    });
    handle(IPC.setDeveloperMode, (on: boolean) => setDeveloperMode(on === true));
    handle(IPC.getUpdate, () => getUpdateStatus());
    handle(IPC.checkForUpdates, () => checkForUpdates());
    handle(IPC.installUpdate, () => installUpdate());
    handle(IPC.openReleases, () => shell.openExternal(ALL_RELEASES_PAGE));
    // Needs the sending window, so not through handle().
    ipcMain.handle(IPC.fitContent, (event, height: unknown) => {
      if (!trusted(event)) throw new Error('untrusted sender');
      const win = BrowserWindow.fromWebContents(event.sender);
      if (win && typeof height === 'number' && Number.isFinite(height) && height > 0) fitContent(win, height);
    });
  }
}

/**
 * Where agent tokens are encrypted. Signed builds and Windows use safeStorage
 * (Keychain / DPAPI). Free macOS builds seal them to the Secure Enclave, so
 * the keychain never prompts after an update. A free build on a Mac without a
 * Secure Enclave falls back to safeStorage, which with the mock keychain only
 * obscures the token; it's still useless without the session key.
 */
function tokenCipher(sealer: Sealer): TokenCipher {
  if (AVOID_KEYCHAIN && sealer.sealingAvailable()) return sealedTokenCipher(sealer);
  return {
    isAvailable: () => safeStorage.isEncryptionAvailable(),
    encrypt: (plain) => safeStorage.encryptString(plain),
    decrypt: (cipher) => safeStorage.decryptString(cipher),
  };
}

function toProgressView(p: PairingProgress): PairingProgressView {
  return p.stage === 'paired' ? { stage: 'paired', serverName: p.server.name, rebound: p.rebound } : p;
}
