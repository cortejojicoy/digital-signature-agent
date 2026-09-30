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
  getJob: (id) => ipcRenderer.invoke(IPC.getJob, String(id)),
  approveJob: (id) => ipcRenderer.invoke(IPC.approveJob, String(id)),
  rejectJob: (id) => ipcRenderer.invoke(IPC.rejectJob, String(id)),
  unpair: (serverId) => ipcRenderer.invoke(IPC.unpair, String(serverId)),
  onStatusChanged: (cb) => subscribe(IPC.statusChanged, cb),
  onPairingProgress: (cb) => subscribe(IPC.pairingProgress, cb),
  onPairPrefill: (cb) => subscribe(IPC.pairPrefill, cb),
  onJobState: (cb) => subscribe(IPC.jobState, cb),
};

contextBridge.exposeInMainWorld('agent', bridge);
