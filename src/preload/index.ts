// contextBridge API (desktop-agent-plan.md §7.1). The renderer is sandboxed
// and gets only these calls.
import { contextBridge, ipcRenderer, webUtils, type IpcRendererEvent } from 'electron';

import { IPC, type AgentBridge } from '../shared/ipc';

function subscribe<T>(channel: string, cb: (payload: T) => void): () => void {
  const listener = (_event: IpcRendererEvent, payload: T) => cb(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

/** A dropped file's path; '' for anything that isn't a file on disk (the main process then refuses it). */
function pathOf(file: File): string {
  try {
    return webUtils.getPathForFile(file);
  } catch {
    return '';
  }
}

const bridge: AgentBridge = {
  getStatus: () => ipcRenderer.invoke(IPC.getStatus),
  startPairing: (input) =>
    ipcRenderer.invoke(IPC.startPairing, {
      origin: String(input.origin),
      code: String(input.code),
      password: typeof input.password === 'string' ? input.password : undefined,
    }),
  previewPairing: (input) => ipcRenderer.invoke(IPC.previewPairing, { origin: String(input.origin), code: String(input.code) }),
  cancelPairing: () => ipcRenderer.invoke(IPC.cancelPairing),
  confirmRepair: (repair) => ipcRenderer.invoke(IPC.confirmRepair, repair === true),
  getJob: (id) => ipcRenderer.invoke(IPC.getJob, String(id)),
  approveJob: (id, opts) =>
    ipcRenderer.invoke(IPC.approveJob, String(id), {
      password: typeof opts?.password === 'string' ? opts.password : undefined,
    }),
  rejectJob: (id) => ipcRenderer.invoke(IPC.rejectJob, String(id)),
  unpair: (serverId, opts) =>
    ipcRenderer.invoke(IPC.unpair, String(serverId), { offline: opts?.offline === 'remove' ? 'remove' : 'ask' }),
  retryRevokes: (origin) => ipcRenderer.invoke(IPC.retryRevokes, String(origin)),
  openDevicesPage: () => ipcRenderer.invoke(IPC.openDevicesPage),
  setDeveloperMode: (on) => ipcRenderer.invoke(IPC.setDeveloperMode, on === true),
  getUpdate: () => ipcRenderer.invoke(IPC.getUpdate),
  checkForUpdates: () => ipcRenderer.invoke(IPC.checkForUpdates),
  installUpdate: () => ipcRenderer.invoke(IPC.installUpdate),
  openReleases: () => ipcRenderer.invoke(IPC.openReleases),
  setKeyStorage: (storage) => ipcRenderer.invoke(IPC.setKeyStorage, storage === 'pkcs12' ? 'pkcs12' : 'platform'),
  chooseCertificateFile: () => ipcRenderer.invoke(IPC.chooseCertificateFile),
  inspectCertificate: (input) =>
    ipcRenderer.invoke(IPC.inspectCertificate, { token: String(input.token), password: String(input.password) }),
  importCertificate: (input) =>
    ipcRenderer.invoke(IPC.importCertificate, { token: String(input.token), password: String(input.password) }),
  removeCertificate: (id) => ipcRenderer.invoke(IPC.removeCertificate, String(id)),
  switchKeyStorage: (storage, opts) =>
    ipcRenderer.invoke(IPC.switchKeyStorage, storage === 'pkcs12' ? 'pkcs12' : 'platform', {
      removeCertificate: opts?.removeCertificate === true,
    }),
  chooseAndVerifyPdf: () => ipcRenderer.invoke(IPC.chooseAndVerifyPdf),
  // The page hands over a File from a drop, never a path of its own choosing.
  verifyDroppedFile: (file) => ipcRenderer.invoke(IPC.verifyPdf, pathOf(file)),
  openVerifiedPdf: (token) => ipcRenderer.invoke(IPC.openVerifiedPdf, String(token)),
  onStatusChanged: (cb) => subscribe(IPC.statusChanged, cb),
  onPairingProgress: (cb) => subscribe(IPC.pairingProgress, cb),
  onPairPrefill: (cb) => subscribe(IPC.pairPrefill, cb),
  onJobState: (cb) => subscribe(IPC.jobState, cb),
  onUpdateChanged: (cb) => subscribe(IPC.updateChanged, cb),
  onVerifyRequested: (cb) => subscribe(IPC.verifyRequested, cb),
  onVerifyFinished: (cb) => subscribe(IPC.verifyFinished, cb),
};

contextBridge.exposeInMainWorld('agent', bridge);
