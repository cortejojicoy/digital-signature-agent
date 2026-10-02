// contextBridge API (desktop-agent-plan.md §7.1). The renderer is sandboxed
// and gets only these calls.
import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';

import { IPC, type AgentBridge } from '../shared/ipc';

function subscribe<T>(channel: string, cb: (payload: T) => void): () => void {
  const listener = (_event: IpcRendererEvent, payload: T) => cb(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

const bridge: AgentBridge = {
  getStatus: () => ipcRenderer.invoke(IPC.getStatus),
  startPairing: (input) => ipcRenderer.invoke(IPC.startPairing, { origin: String(input.origin), code: String(input.code) }),
  cancelPairing: () => ipcRenderer.invoke(IPC.cancelPairing),
  confirmRepair: (repair) => ipcRenderer.invoke(IPC.confirmRepair, repair === true),
  getJob: (id) => ipcRenderer.invoke(IPC.getJob, String(id)),
  approveJob: (id) => ipcRenderer.invoke(IPC.approveJob, String(id)),
  rejectJob: (id) => ipcRenderer.invoke(IPC.rejectJob, String(id)),
  unpair: (serverId) => ipcRenderer.invoke(IPC.unpair, String(serverId)),
  setDeveloperMode: (on) => ipcRenderer.invoke(IPC.setDeveloperMode, on === true),
  getUpdate: () => ipcRenderer.invoke(IPC.getUpdate),
  checkForUpdates: () => ipcRenderer.invoke(IPC.checkForUpdates),
  installUpdate: () => ipcRenderer.invoke(IPC.installUpdate),
  openReleases: () => ipcRenderer.invoke(IPC.openReleases),
  fitContent: (height) => ipcRenderer.invoke(IPC.fitContent, Number(height)),
  onStatusChanged: (cb) => subscribe(IPC.statusChanged, cb),
  onPairingProgress: (cb) => subscribe(IPC.pairingProgress, cb),
  onPairPrefill: (cb) => subscribe(IPC.pairPrefill, cb),
  onJobState: (cb) => subscribe(IPC.jobState, cb),
  onUpdateChanged: (cb) => subscribe(IPC.updateChanged, cb),
};

contextBridge.exposeInMainWorld('agent', bridge);
