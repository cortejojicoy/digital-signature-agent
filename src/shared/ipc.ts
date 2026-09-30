// IPC contract between the main process and the renderer (desktop-agent-plan.md §7.1).
// Deliberately narrow: there is no generic sign(bytes).

export const IPC = {
  getStatus: 'agent:get-status',
  startPairing: 'agent:start-pairing',
  cancelPairing: 'agent:cancel-pairing',
  getJob: 'agent:get-job',
  approveJob: 'agent:approve-job',
  rejectJob: 'agent:reject-job',
  unpair: 'agent:unpair',
  // main → renderer events
  statusChanged: 'agent:status-changed',
  pairingProgress: 'agent:pairing-progress',
  pairPrefill: 'agent:pair-prefill',
  jobState: 'agent:job-state',
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
}

export interface StatusView {
  version: string;
  platform: 'macos' | 'windows' | 'other';
  capabilities: { hardware: boolean; userPresence: boolean; attestation: boolean };
  servers: ServerView[];
}

export type PairingProgressView =
  | { stage: 'looking_up' }
  | { stage: 'creating_keys'; serverName: string }
  | { stage: 'awaiting_confirmation'; serverName: string; origin: string; deviceLabel: string }
  | { stage: 'paired'; serverName: string };

export type PairingResult = { ok: true; serverName: string } | { ok: false; error: string };

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
  getJob(id: string): Promise<JobView | null>;
  approveJob(id: string): Promise<void>;
  rejectJob(id: string): Promise<void>;
  unpair(serverId: string): Promise<void>;
  onStatusChanged(cb: () => void): () => void;
  onPairingProgress(cb: (p: PairingProgressView) => void): () => void;
  onPairPrefill(cb: (p: { origin: string; code: string }) => void): () => void;
  onJobState(cb: (s: JobState & { id: string }) => void): () => void;
}
