// IPC contract between the main process and the renderer (desktop-agent-plan.md §7.1).
// Deliberately narrow: there is no generic sign(bytes).
import type { DeviceType } from '../main/device-type';

export type { DeviceType };

export const IPC = {
  getStatus: 'agent:get-status',
  startPairing: 'agent:start-pairing',
  cancelPairing: 'agent:cancel-pairing',
  confirmRepair: 'agent:confirm-repair',
  getJob: 'agent:get-job',
  approveJob: 'agent:approve-job',
  rejectJob: 'agent:reject-job',
  unpair: 'agent:unpair',
  setDeveloperMode: 'agent:set-developer-mode',
  getUpdate: 'agent:get-update',
  checkForUpdates: 'agent:check-for-updates',
  installUpdate: 'agent:install-update',
  // main → renderer events
  statusChanged: 'agent:status-changed',
  pairingProgress: 'agent:pairing-progress',
  pairPrefill: 'agent:pair-prefill',
  jobState: 'agent:job-state',
  updateChanged: 'agent:update-changed',
} as const;

export type ProtectionLevel = 'secure_enclave' | 'tpm' | 'software';

export interface ServerView {
  id: string;
  name: string;
  origin: string;
  userName: string;
  deviceLabel: string;
  protection: ProtectionLevel;
  userPresence: boolean;
  pairedAt: string;
  /** Paired over plain http:// (Developer mode). */
  insecure: boolean;
  deviceType: DeviceType;
  /** The same account's other signing devices for this app. */
  otherDevices: Array<{ label: string; deviceType: DeviceType | null }>;
}

export interface StatusView {
  version: string;
  platform: 'macos' | 'windows' | 'other';
  capabilities: { hardware: boolean; userPresence: boolean; attestation: boolean };
  servers: ServerView[];
  /** `locked`: always on under npm run dev. */
  developerMode: { on: boolean; locked: boolean };
}

export interface ReleaseView {
  version: string;
  name: string;
  notes: string;
  url: string;
  publishedAt: string;
}

export type UpdateView =
  | { state: 'idle' }
  | { state: 'checking' }
  | { state: 'up_to_date'; checkedAt: string }
  /** `install`: download in place, or open the release page (free macOS builds, npm run dev). */
  | { state: 'available'; release: ReleaseView; install: 'download' | 'open_page' }
  | { state: 'downloading'; release: ReleaseView; percent: number }
  | { state: 'ready'; release: ReleaseView }
  | { state: 'error'; message: string };

export type PairingProgressView =
  | { stage: 'looking_up' }
  /** Answer with confirmRepair(true | false). */
  | { stage: 'already_paired_locally'; serverName: string; userName: string }
  | { stage: 'creating_keys'; serverName: string }
  | {
      stage: 'awaiting_confirmation';
      serverName: string;
      origin: string;
      deviceLabel: string;
      existingDevice?: { label: string; deviceType?: DeviceType };
    }
  | { stage: 'paired'; serverName: string; rebound: boolean };

export type PairingResult =
  | { ok: true; serverName: string; rebound: boolean }
  /** `serverId` with code app_already_paired: the pairing to unpair first. */
  | { ok: false; error: string; code?: string; serverId?: string; serverName?: string };

export interface JobView {
  id: string;
  serverName: string;
  origin: string;
  documentTitle: string;
  signerName: string;
  purpose: string;
  expiresAt: string;
  protection: ProtectionLevel;
  userPresence: boolean;
  deviceType: DeviceType;
}

export type JobState =
  | { state: 'waiting_for_os_prompt' }
  | { state: 'completed' }
  | { state: 'rejected'; reason: string }
  | { state: 'failed'; error: string };

/** What the preload exposes as window.agent. */
export interface AgentBridge {
  getStatus(): Promise<StatusView>;
  startPairing(input: { origin: string; code: string }): Promise<PairingResult>;
  cancelPairing(): Promise<void>;
  /** Answers an `already_paired_locally` progress: true re-pairs, false stops. */
  confirmRepair(repair: boolean): Promise<void>;
  getJob(id: string): Promise<JobView | null>;
  approveJob(id: string): Promise<void>;
  rejectJob(id: string): Promise<void>;
  unpair(serverId: string): Promise<void>;
  setDeveloperMode(on: boolean): Promise<void>;
  getUpdate(): Promise<UpdateView>;
  checkForUpdates(): Promise<void>;
  /** Downloads, restarts to install, or opens the release page, depending on the state. */
  installUpdate(): Promise<void>;
  onStatusChanged(cb: () => void): () => void;
  onPairingProgress(cb: (p: PairingProgressView) => void): () => void;
  onPairPrefill(cb: (p: { origin: string; code: string }) => void): () => void;
  onJobState(cb: (s: JobState & { id: string }) => void): () => void;
  onUpdateChanged(cb: (u: UpdateView) => void): () => void;
}
