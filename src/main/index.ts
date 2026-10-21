// App lifecycle, single-instance lock, protocol links, tray and windows
// (desktop-agent-plan.md §7).
import { X509Certificate, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  nativeTheme,
  net,
  Notification,
  safeStorage,
  session,
  shell,
  Tray,
  type IpcMainInvokeEvent,
} from 'electron';

import {
  IPC,
  type CertificateErrorView,
  type CertificateFileResult,
  type CertificateImportResult,
  type CertificatePreviewResult,
  type CertificateRemoveResult,
  type CertificateView,
  type JobState,
  type JobView,
  type KeyStorageView,
  type PairingPreviewResult,
  type PairingProgressView,
  type SwitchResultView,
  type PairingResult,
  type StatusView,
  type UpdateView,
  type VerifyResult,
} from '../shared/ipc';
import { Agent, type CertificateSummary } from './agent';
import { CertificateError, CertificateStore } from './certificates';
import { APP_ORIGIN, appUrl, handleAppScheme, registerAppScheme } from './app-protocol';
import type { Approval, ConfirmRequest, JobOutcome, RetryReason } from './jobs';
import { loadNativeKeyStore, type Capabilities, type KeySource, type Sealer } from './keystore';
import { PairingError, type PairingProgress } from './pairing';
import { SCHEME, linkFromArgv, pdfFromArgv } from './protocol';
import { AVOID_KEYCHAIN } from './build-info';
import { SettingsStore } from './settings';
import { Store, sealedTokenCipher, type TokenCipher } from './store';
import { ALL_RELEASES_PAGE } from './release';
import { checkForUpdates, getUpdateStatus, installUpdate, startUpdater } from './updater';
import { PdfFileError, PdfVerifier, readPdfFile } from './verify/verifier';

const APP_ROOT = path.join(__dirname, '..', '..');
const RENDERER_DIR = path.join(APP_ROOT, 'dist', 'renderer');
const PRELOAD = path.join(APP_ROOT, 'dist', 'preload', 'index.js');
const DEV = !app.isPackaged;

// Every window has one fixed size; only the paired apps list scrolls.
const WINDOW_WIDTH = 460;
const WINDOW_HEIGHT = 608;
// The page's background, so a window never flashes white before it paints.
const WINDOW_BACKGROUND = '#111113';

// A chosen .p12 waits in memory for its password this long (pkcs12-key-storage-plan.md §6.3).
const CERTIFICATE_FILE_TTL_MS = 5 * 60_000;
const MAX_CERTIFICATE_FILE = 64 * 1024;
// Checked PDFs the page may ask to open in the PDF viewer, by token.
const MAX_VERIFIED_FILES = 20;

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
  // The .p12 the user picked, held here so the page never sees its path or bytes.
  let certificateFile: { token: string; name: string; data: Buffer; expires: number } | null = null;
  // Verify a PDF: files opened with the agent before `ready`, and the paths
  // behind the tokens the page holds (it never sees a path itself).
  let verifier: PdfVerifier | null = null;
  const pendingFiles: string[] = [];
  const verifiedFiles = new Map<string, string>();
  let verifyRequests = 0;

  interface PendingConfirm {
    request: ConfirmRequest;
    window: BrowserWindow;
    resolve: (answer: Approval) => void;
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
  // macOS delivers "Open With" files via open-file, possibly before `ready`.
  app.on('open-file', (event, filePath) => {
    event.preventDefault();
    openFileFromOs(filePath);
  });
  // Windows delivers links, and files opened with the agent, in the argv of a second launch.
  app.on('second-instance', (_event, argv, workingDirectory) => {
    const link = linkFromArgv(argv);
    const pdf = link ? null : pdfFromArgv(argv);
    if (link) deliver(link);
    else if (pdf) openFileFromOs(path.resolve(workingDirectory, pdf));
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
    // Dark by default, whatever the system appearance.
    nativeTheme.themeSource = 'dark';
    handleAppScheme(RENDERER_DIR);
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    session.defaultSession.setDevicePermissionHandler(() => false);
    if (process.platform === 'darwin') app.dock?.hide();

    const keystore = loadNativeKeyStore(APP_ROOT, { keyDirectory: path.join(app.getPath('userData'), 'keys') });
    const store = new Store(app.getPath('userData'), tokenCipher(keystore));
    await store.load();
    settings = new SettingsStore(app.getPath('userData'));
    const saved = await settings.load();
    developerMode = DEV || saved.developerMode;
    // People who paired before the chooser existed keep their security-chip keys, unasked.
    if (saved.keyStorage === null && store.list().length > 0) await settings.update({ keyStorage: 'platform' });
    const certificates = new CertificateStore(app.getPath('userData'));
    await certificates.load();

    // In Developer mode, requests go through Chromium's network stack, which
    // trusts the OS certificate store, so Herd / Valet / mkcert HTTPS works
    // for local testing. Otherwise Node's fetch and its bundled CA list.
    const agentFetch = (input: string, init: RequestInit) => (developerMode ? net.fetch(input, init) : fetch(input, init));

    agent = new Agent({
      keystore,
      store,
      agentVersion: app.getVersion(),
      allowInsecureLocalNetwork: developerMode,
      fetch: agentFetch,
      biometryOnly: process.env.KUKUX_BIOMETRY_ONLY === '1',
      certificates,
      keyStorage: () => settings?.get().keyStorage ?? null,
      confirm: openConfirm,
      parentWindow: () => activeConfirm?.window.getNativeWindowHandle(),
      onPairLink: (link) => {
        const win = showMainWindow();
        // Certificate mode pairs on the password screen, without address or code fields
        // (certificate-password-pairing-plan.md §3.1).
        const certificate = settings?.get().keyStorage === 'pkcs12';
        const send = () => win.webContents.send(IPC.pairPrefill, { origin: link.origin, code: link.code, certificate });
        if (win.webContents.isLoading()) win.webContents.once('did-finish-load', send);
        else send();
      },
      onJobOutcome: handleOutcome,
      onServersChanged: broadcastStatus,
    });

    verifier = new PdfVerifier({
      // Paired apps only, in pairing order; plain-HTTP ones only in Developer mode, as for signing.
      targets: () =>
        store
          .list()
          .filter((s) => developerMode || s.origin.startsWith('https://'))
          .map((s) => ({ origin: s.origin, name: s.name })),
      anchors: store,
      fetch: agentFetch,
    });

    registerIpc();
    // Device types for older pairings, and revokes left over from an offline unpair.
    void agent.init().catch(() => {});
    setInterval(() => void agent?.retryRevokes().catch(() => {}), 60 * 60_000);
    createTray();
    startUpdater(broadcastUpdate);

    const initial = linkFromArgv(process.argv);
    if (initial) pendingLinks.push(initial);
    const initialPdf = initial ? null : pdfFromArgv(process.argv);
    if (initialPdf) pendingFiles.push(path.resolve(initialPdf));
    for (const link of pendingLinks.splice(0)) void agent.handleLink(link);
    if (store.list().length === 0) showMainWindow();
    for (const file of pendingFiles.splice(0)) openFileFromOs(file);
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
      height: WINDOW_HEIGHT,
      useContentSize: true,
      backgroundColor: WINDOW_BACKGROUND,
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

  function openConfirm(request: ConfirmRequest, retry?: RetryReason): Promise<Approval> {
    // A wrong certificate password: ask again in the window that's already open (§4.3).
    if (retry) {
      const pending = confirms.get(request.job.uuid);
      if (!pending || pending.window.isDestroyed()) return Promise.resolve(false);
      return new Promise((resolve) => {
        pending.resolve = resolve;
        pending.decided = false;
        if (activeConfirm === pending) activeConfirm = null;
        sendJobState(request.job.uuid, { state: 'password_rejected', error: retry.error, code: retry.code, retryAt: retry.retryAt });
      });
    }
    return new Promise((resolve) => {
      const window = new BrowserWindow({
        width: WINDOW_WIDTH,
        height: WINDOW_HEIGHT,
        useContentSize: true,
        backgroundColor: WINDOW_BACKGROUND,
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
      window.once('ready-to-show', () => {
        window.show();
        window.focus();
        app.focus();
      });
    });
  }

  function decide(jobId: string, approved: boolean, password?: string): void {
    const pending = confirms.get(jobId);
    if (!pending || pending.decided) return;
    pending.decided = true;
    if (approved) {
      // Keep the window open as the parent of the Touch ID / Hello prompt,
      // or to ask again if the certificate password is wrong.
      activeConfirm = pending;
      sendJobState(jobId, { state: password === undefined ? 'waiting_for_os_prompt' : 'signing' });
    } else if (!pending.window.isDestroyed()) {
      pending.window.close();
    }
    pending.resolve(approved ? { approved, password } : false);
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
          { label: 'Verify a PDF…', click: () => void chooseFromTray() },
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

  // ── Key storage and certificates (pkcs12-key-storage-plan.md §6.3, §7) ──

  function keyStorageView(caps: Capabilities): KeyStorageView {
    const summaries = agent!.certificateSummaries();
    const active = summaries.find((c) => c.active) ?? null;
    return {
      selected: settings!.get().keyStorage,
      platform: {
        available: caps.hardware,
        label: process.platform === 'win32' ? 'TPM' : 'Secure Enclave',
      },
      certificatesSupported: caps.pkcs12,
      certificate: active ? certificateView(active) : null,
      olderCertificates: summaries.filter((c) => !c.active).map(certificateView),
    };
  }

  async function setKeyStorage(storage: KeySource): Promise<void> {
    await settings!.update({ keyStorage: storage });
    broadcastStatus();
  }

  function dropCertificateFile(): void {
    certificateFile?.data.fill(0);
    certificateFile = null;
  }

  function takeCertificateFile(token: string): Buffer | null {
    if (!certificateFile || certificateFile.token !== token) return null;
    if (Date.now() > certificateFile.expires) {
      dropCertificateFile();
      return null;
    }
    return certificateFile.data;
  }

  async function chooseCertificateFile(): Promise<CertificateFileResult | null> {
    const options: Electron.OpenDialogOptions = {
      title: 'Choose your certificate',
      buttonLabel: 'Choose',
      properties: ['openFile'],
      filters: [{ name: 'Certificate (PKCS#12)', extensions: ['p12', 'pfx'] }],
    };
    const picked = mainWindow ? await dialog.showOpenDialog(mainWindow, options) : await dialog.showOpenDialog(options);
    const file = picked.filePaths[0];
    if (picked.canceled || !file) return null;
    const stat = await fs.stat(file).catch(() => null);
    if (!stat?.isFile()) return { ok: false, error: "That file can't be read.", code: 'E_BAD_FILE' };
    if (stat.size === 0 || stat.size > MAX_CERTIFICATE_FILE) {
      return { ok: false, error: "That doesn't look like a certificate file (.p12 or .pfx).", code: 'E_BAD_FILE' };
    }
    dropCertificateFile();
    certificateFile = {
      token: randomBytes(16).toString('hex'),
      name: path.basename(file),
      data: await fs.readFile(file),
      expires: Date.now() + CERTIFICATE_FILE_TTL_MS,
    };
    return { ok: true, token: certificateFile.token, fileName: certificateFile.name };
  }

  // ── Verify a PDF ──

  /** Reads and checks a file in this process; the page gets the verdict and a token, never the bytes or path. */
  async function verifyFile(filePath: string): Promise<VerifyResult> {
    const fileName = typeof filePath === 'string' ? path.basename(filePath) : '';
    try {
      const file = await readPdfFile(filePath);
      const report = await verifier!.verify(file.bytes);
      return { ok: true, token: rememberVerifiedFile(filePath), fileName: file.name, size: file.size, ...report };
    } catch (err) {
      if (err instanceof PdfFileError) return { ok: false, error: err.message, code: err.code, fileName };
      return { ok: false, error: "That file couldn't be checked.", code: 'unreadable', fileName };
    }
  }

  function rememberVerifiedFile(filePath: string): string {
    const token = randomBytes(16).toString('hex');
    verifiedFiles.set(token, filePath);
    while (verifiedFiles.size > MAX_VERIFIED_FILES) verifiedFiles.delete(verifiedFiles.keys().next().value!);
    return token;
  }

  /** A PDF opened with the agent from Finder / Explorer: show the window, then the verdict. */
  function openFileFromOs(filePath: string): void {
    if (!verifier) {
      pendingFiles.push(filePath);
      return;
    }
    const id = ++verifyRequests;
    const win = showMainWindow();
    if (process.platform === 'darwin') app.focus({ steal: true });
    const send = (channel: string, payload: unknown) => {
      if (win.isDestroyed()) return;
      if (win.webContents.isLoading()) win.webContents.once('did-finish-load', () => win.webContents.send(channel, payload));
      else win.webContents.send(channel, payload);
    };
    send(IPC.verifyRequested, { id, fileName: path.basename(filePath) });
    void verifyFile(filePath).then((result) => send(IPC.verifyFinished, { id, result }));
  }

  async function choosePdf(): Promise<string | null> {
    const options: Electron.OpenDialogOptions = {
      title: 'Choose a PDF to verify',
      buttonLabel: 'Verify',
      properties: ['openFile'],
      filters: [{ name: 'PDF document', extensions: ['pdf'] }],
    };
    const picked = mainWindow ? await dialog.showOpenDialog(mainWindow, options) : await dialog.showOpenDialog(options);
    return picked.canceled ? null : (picked.filePaths[0] ?? null);
  }

  async function chooseFromTray(): Promise<void> {
    const file = await choosePdf();
    if (file) openFileFromOs(file);
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
      const capabilities = await agent!.capabilities();
      return {
        version: app.getVersion(),
        platform: process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'other',
        capabilities,
        servers: agent!.servers(),
        pendingRevokes: agent!.pendingRevokes(),
        keyStorage: keyStorageView(capabilities),
        developerMode: { on: developerMode, locked: DEV },
      };
    });

    handle(IPC.previewPairing, async (input: { origin: string; code: string }): Promise<PairingPreviewResult> => {
      try {
        const preview = await agent!.previewPairing(String(input.origin), String(input.code));
        return {
          ok: true,
          preview: {
            serverName: preview.serverName,
            origin: preview.origin,
            host: new URL(preview.origin).host,
            userName: preview.userName,
            certificateName: preview.certificateName ?? '',
            repair: preview.repair,
          },
        };
      } catch (err) {
        if (err instanceof PairingError) {
          devicesPage = err.manageUrl ?? null;
          return { ok: false, error: err.message, code: err.code, manageUrl: err.manageUrl };
        }
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    });

    handle(IPC.switchKeyStorage, async (storage: unknown, opts?: { removeCertificate?: unknown }): Promise<SwitchResultView> => {
      const next: KeySource = storage === 'pkcs12' ? 'pkcs12' : 'platform';
      const result = await agent!.switchKeyStorage(next, { removeCertificate: opts?.removeCertificate === true });
      await setKeyStorage(next);
      return result;
    });

    handle(IPC.startPairing, async (input: { origin: string; code: string; password?: string }): Promise<PairingResult> => {
      pairingAbort?.abort();
      const abort = new AbortController();
      pairingAbort = abort;
      devicesPage = null;
      try {
        let rebound = false;
        const server = await agent!.pair(input.origin, input.code, {
          password: typeof input.password === 'string' ? input.password : undefined,
          signal: abort.signal,
          onProgress: (p) => {
            if (p.stage === 'paired') rebound = p.rebound;
            mainWindow?.webContents.send(IPC.pairingProgress, toProgressView(p));
          },
          // The password screen already said "pairing again replaces it" (§3.5): no second question.
          confirmRepair: typeof input.password === 'string' ? undefined : () =>
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
        certificateName: agent!.servers().find((s) => s.id === server.id)?.certificateName,
        passwordRequired: server.keySource === 'pkcs12',
      };
    });

    handle(IPC.approveJob, (id: string, opts?: { password?: unknown }) =>
      decide(id, true, typeof opts?.password === 'string' ? opts.password : undefined),
    );
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
    handle(IPC.setKeyStorage, (storage: unknown) => setKeyStorage(storage === 'pkcs12' ? 'pkcs12' : 'platform'));
    handle(IPC.chooseCertificateFile, () => chooseCertificateFile());
    handle(IPC.inspectCertificate, async (input: { token?: unknown; password?: unknown }): Promise<CertificatePreviewResult> => {
      const data = takeCertificateFile(String(input?.token ?? ''));
      if (!data) return fileExpired();
      try {
        const preview = await agent!.inspectCertificate(data, String(input?.password ?? ''));
        return {
          ok: true,
          preview: {
            commonName: preview.commonName,
            organization: preview.organization,
            subject: preview.subject,
            issuerName: preview.issuerName,
            serialHex: preview.serialHex,
            notBefore: preview.notBefore,
            notAfter: preview.notAfter,
            fingerprint256: preview.fingerprint256,
            algorithm: preview.algorithm === 'RS256' ? `RSA ${preview.keyBits}` : 'ECDSA P-256',
            keyBits: preview.keyBits,
            pnpki: preview.pnpki,
            chain: preview.chain.map((der) => commonNameOf(der)),
            warnings: preview.warnings.map((w) => w.message),
            alreadyImported: preview.alreadyImported,
          },
        };
      } catch (err) {
        return certificateFailure(err);
      }
    });
    handle(IPC.importCertificate, async (input: { token?: unknown; password?: unknown }): Promise<CertificateImportResult> => {
      const data = takeCertificateFile(String(input?.token ?? ''));
      if (!data) return fileExpired();
      try {
        const imported = await agent!.importCertificate(data, String(input?.password ?? ''));
        dropCertificateFile();
        // Select it only when nothing would be unpaired; otherwise the chooser
        // asks first (certificate-password-pairing-plan.md §5.2).
        if (agent!.pairingsOutside('pkcs12').length === 0) await setKeyStorage('pkcs12');
        const summary = agent!.certificateSummaries().find((c) => c.id === imported.id)!;
        return { ok: true, certificate: certificateView(summary) };
      } catch (err) {
        return certificateFailure(err);
      }
    });
    handle(IPC.chooseAndVerifyPdf, async (): Promise<VerifyResult | null> => {
      const file = await choosePdf();
      return file ? verifyFile(file) : null;
    });
    // A path from a drop (preload, webUtils.getPathForFile). readPdfFile checks it: absolute, a file, ≤ 50 MB, %PDF-.
    handle(IPC.verifyPdf, (filePath: unknown) => verifyFile(typeof filePath === 'string' ? filePath : ''));
    handle(IPC.openVerifiedPdf, async (token: unknown): Promise<{ ok: boolean; error?: string }> => {
      const file = verifiedFiles.get(String(token));
      if (!file) return { ok: false, error: 'Check the file again to open it.' };
      const error = await shell.openPath(file);
      return error ? { ok: false, error } : { ok: true };
    });
    handle(IPC.removeCertificate, async (id: unknown): Promise<CertificateRemoveResult> => {
      try {
        await agent!.removeCertificate(String(id));
        return { ok: true };
      } catch (err) {
        return certificateFailure(err);
      }
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

const EXPIRY_WARNING_MS = 30 * 86_400_000;

function certificateView(c: CertificateSummary): CertificateView {
  return {
    id: c.id,
    commonName: c.commonName,
    organization: c.organization,
    subject: c.subject,
    issuer: c.issuer,
    issuerName: c.issuerName,
    serialHex: c.serialHex,
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    fingerprint256: c.fingerprint256,
    pnpki: c.pnpki,
    protection: c.protection,
    userPresence: c.userPresence,
    active: c.active,
    usedBy: c.usedBy,
    expiresSoon: Date.parse(c.notAfter) - Date.now() < EXPIRY_WARNING_MS,
  };
}

function certificateFailure(err: unknown): CertificateErrorView {
  if (err instanceof CertificateError) return { ok: false, error: err.message, code: err.code };
  return { ok: false, error: err instanceof Error ? err.message : String(err) };
}

function fileExpired(): CertificateErrorView {
  return { ok: false, error: 'Choose the certificate file again.', code: 'file_expired' };
}

/** "CN=…" of a DER certificate, for the preview's chain list. Public data. */
function commonNameOf(der: Buffer): string {
  try {
    const subject = new X509Certificate(der).subject.split('\n');
    return subject.find((line) => line.startsWith('CN='))?.slice(3) ?? subject.join(', ');
  } catch {
    return 'Unreadable certificate';
  }
}

function toProgressView(p: PairingProgress): PairingProgressView {
  return p.stage === 'paired' ? { stage: 'paired', serverName: p.server.name, rebound: p.rebound } : p;
}
