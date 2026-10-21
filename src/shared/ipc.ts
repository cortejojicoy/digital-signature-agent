// IPC contract between the main process and the renderer (desktop-agent-plan.md §7.1).
// Deliberately narrow: there is no generic sign(bytes).
import type { PendingRevokeSummary, UnpairResult } from '../main/agent';
import type { DeviceType } from '../main/device-type';
import type { Inspection, LookupRecord, Verdict } from './verdict';

export type { DeviceType, PendingRevokeSummary, UnpairResult };

export const IPC = {
  getStatus: 'agent:get-status',
  startPairing: 'agent:start-pairing',
  cancelPairing: 'agent:cancel-pairing',
  confirmRepair: 'agent:confirm-repair',
  getJob: 'agent:get-job',
  approveJob: 'agent:approve-job',
  rejectJob: 'agent:reject-job',
  unpair: 'agent:unpair',
  retryRevokes: 'agent:retry-revokes',
  openDevicesPage: 'agent:open-devices-page',
  setDeveloperMode: 'agent:set-developer-mode',
  getUpdate: 'agent:get-update',
  checkForUpdates: 'agent:check-for-updates',
  installUpdate: 'agent:install-update',
  openReleases: 'agent:open-releases',
  // Key storage and certificates (pkcs12-key-storage-plan.md §7.6)
  setKeyStorage: 'agent:set-key-storage',
  chooseCertificateFile: 'agent:choose-certificate-file',
  inspectCertificate: 'agent:inspect-certificate',
  importCertificate: 'agent:import-certificate',
  removeCertificate: 'agent:remove-certificate',
  // Certificate password and one storage at a time (certificate-password-pairing-plan.md §7.3)
  previewPairing: 'agent:preview-pairing',
  switchKeyStorage: 'agent:switch-key-storage',
  // Verify a PDF: the main process reads and checks the file; the page gets the verdict
  chooseAndVerifyPdf: 'agent:choose-and-verify-pdf',
  verifyPdf: 'agent:verify-pdf',
  openVerifiedPdf: 'agent:open-verified-pdf',
  // main → renderer events
  statusChanged: 'agent:status-changed',
  pairingProgress: 'agent:pairing-progress',
  pairPrefill: 'agent:pair-prefill',
  jobState: 'agent:job-state',
  updateChanged: 'agent:update-changed',
  verifyRequested: 'agent:verify-requested',
  verifyFinished: 'agent:verify-finished',
} as const;

export type ProtectionLevel = 'secure_enclave' | 'tpm' | 'software';
/** Where a pairing's signing key comes from: the security chip, or an imported certificate. */
export type KeySourceView = 'platform' | 'pkcs12';

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
  keySource: KeySourceView;
  /** keySource 'pkcs12': the certificate's name. */
  certificateName?: string;
}

/** An imported certificate. Public data only. */
export interface CertificateView {
  id: string;
  commonName: string;
  organization: string;
  subject: string;
  issuer: string;
  issuerName: string;
  serialHex: string;
  notBefore: string;
  notAfter: string;
  fingerprint256: string;
  /** Under a known Philippine PKI root. */
  pnpki: boolean;
  protection: ProtectionLevel;
  userPresence: boolean;
  /** The newest certificate, which new certificate pairings use. */
  active: boolean;
  /** Apps paired with it: "unpair these first". */
  usedBy: string[];
  /** Within 30 days of expiring. */
  expiresSoon: boolean;
}

export interface KeyStorageView {
  /** null until the user chooses (first launch). */
  selected: KeySourceView | null;
  platform: { available: boolean; label: string };
  /** importCertificate works here (macOS 15+, Windows). */
  certificatesSupported: boolean;
  /** The active certificate, if one is imported. */
  certificate: CertificateView | null;
  /** Older certificates that apps still use (§6.6). */
  olderCertificates: CertificateView[];
}

/** What the import screen shows before importing (§7.2). */
export interface CertificatePreviewView {
  commonName: string;
  organization: string;
  subject: string;
  issuerName: string;
  serialHex: string;
  notBefore: string;
  notAfter: string;
  fingerprint256: string;
  algorithm: string;
  keyBits: number;
  pnpki: boolean;
  /** Each certificate's name, leaf first. */
  chain: string[];
  warnings: string[];
  alreadyImported: boolean;
}

export type CertificateErrorView = {
  ok: false;
  error: string;
  /** E_BAD_PASSWORD, E_BAD_FILE, E_UNSUPPORTED, E_KEY_MISMATCH, E_CANCELLED, expired, not_a_signing_certificate, in_use, … */
  code?: string;
};

export type CertificateFileResult = { ok: true; token: string; fileName: string } | CertificateErrorView;
export type CertificatePreviewResult = { ok: true; preview: CertificatePreviewView } | CertificateErrorView;
export type CertificateImportResult = { ok: true; certificate: CertificateView } | CertificateErrorView;
export type CertificateRemoveResult = { ok: true } | CertificateErrorView;

/** "Open in Kukux Sign Agent" in certificate mode: what is about to be paired (§3.2). */
export interface PairingPreviewView {
  serverName: string;
  origin: string;
  /** e.g. amp.up.edu.ph, shown so a look-alike stands out. */
  host: string;
  userName: string;
  certificateName: string;
  /** This account's signature for the app is already here: pairing replaces it. */
  repair: boolean;
}

export type PairingPreviewResult =
  | { ok: true; preview: PairingPreviewView }
  | { ok: false; error: string; code?: string; manageUrl?: string };

/** What switching key storage unpaired, by app name (§5.2). */
export interface SwitchResultView {
  unpaired: string[];
  queued: string[];
  failed: string[];
}

export interface StatusView {
  version: string;
  platform: 'macos' | 'windows' | 'other';
  capabilities: { hardware: boolean; userPresence: boolean; attestation: boolean };
  servers: ServerView[];
  /** Unpairs the server hasn't heard about yet (one-computer-per-account-plan.md §7.1). */
  pendingRevokes: PendingRevokeSummary[];
  keyStorage: KeyStorageView;
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
  /** Answer with confirmRepair(true | false). `from` / `to`: the key storage now, and after re-pairing. */
  | { stage: 'already_paired_locally'; serverName: string; userName: string; from: KeySourceView; to: KeySourceView }
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
  /**
   * `serverId` with code app_already_paired: the pairing to unpair first.
   * `manageUrl` with code account_already_paired: openDevicesPage() opens it.
   */
  | { ok: false; error: string; code?: string; serverId?: string; serverName?: string; manageUrl?: string };

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
  /** The hub app that asked, shown as "<app> asks: <document>". */
  requestingApp?: string;
  /** Purpose `login`: the code the browser shows, and which browser it is. */
  login?: { matchCode: string; browser: string; ip: string };
  /** Purpose `transfer`: whose signature moves, and to which computer. */
  transfer?: { name: string; device: string };
  /** A certificate pairing: the certificate that signs. */
  certificateName?: string;
  /** Approve with the certificate password instead of Touch ID / Hello (§4). */
  passwordRequired: boolean;
}

export type JobState =
  | { state: 'waiting_for_os_prompt' }
  /** Signing with the certificate password. */
  | { state: 'signing' }
  /** The certificate password was wrong (or missing): ask again in the same window. */
  | { state: 'password_rejected'; error: string; code: 'E_BAD_PASSWORD' | 'E_LOCKED'; retryAt?: string }
  | { state: 'completed' }
  | { state: 'rejected'; reason: string }
  | { state: 'failed'; error: string };

/** A checked PDF (main/verify/verifier.ts). Server text in it is shown as text only. */
export interface VerifyReportView {
  ok: true;
  /** Opaque: openVerifiedPdf(token) opens this file. The page never sees its path. */
  token: string;
  fileName: string;
  size: number;
  verdict: Verdict;
  /** false: no app is paired, so only the file's own signature was checked. */
  paired: boolean;
  /** For the wording: the record's issuer, else the paired app's name. */
  issuer: string;
  /** Whose CA the embedded signature was checked against. */
  trustIssuer: string;
  inspection: Inspection;
  record: LookupRecord | null;
  /**
   * Why record is null though apps were asked. "unsupported": none of them
   * has PDF verification yet (an older release), so retrying won't help.
   */
  lookupFailure: 'unsupported' | 'unavailable' | null;
}

export type VerifyFileErrorCode = 'not_found' | 'not_a_file' | 'empty' | 'too_large' | 'not_pdf' | 'unreadable';

export type VerifyResult = VerifyReportView | { ok: false; error: string; code: VerifyFileErrorCode; fileName?: string };

/** A PDF opened with the agent from the OS: `verifyFinished` with the same id follows. */
export interface VerifyRequestedEvent {
  id: number;
  fileName: string;
}

export interface VerifyFinishedEvent {
  id: number;
  result: VerifyResult;
}

/** What the preload exposes as window.agent. */
export interface AgentBridge {
  getStatus(): Promise<StatusView>;
  /** In certificate mode, `password` is the certificate's (§3). */
  startPairing(input: { origin: string; code: string; password?: string }): Promise<PairingResult>;
  /** Looks the code up and runs the early checks; changes nothing (§3.2). */
  previewPairing(input: { origin: string; code: string }): Promise<PairingPreviewResult>;
  cancelPairing(): Promise<void>;
  /** Answers an `already_paired_locally` progress: true re-pairs, false stops. */
  confirmRepair(repair: boolean): Promise<void>;
  getJob(id: string): Promise<JobView | null>;
  /** A certificate job approves with its password; a wrong one comes back as `password_rejected`. */
  approveJob(id: string, opts?: { password?: string }): Promise<void>;
  rejectJob(id: string): Promise<void>;
  /** Tries the server first; `offline: 'remove'` removes locally if it can't be reached. */
  unpair(serverId: string, opts?: { offline?: 'ask' | 'remove' }): Promise<UnpairResult>;
  /** Retries the queued revokes for one app now. */
  retryRevokes(origin: string): Promise<void>;
  /** Opens the devices page from the last account_already_paired failure. */
  openDevicesPage(): Promise<void>;
  setDeveloperMode(on: boolean): Promise<void>;
  getUpdate(): Promise<UpdateView>;
  checkForUpdates(): Promise<void>;
  /** Downloads, restarts to install, or opens the release page, depending on the state. */
  installUpdate(): Promise<void>;
  /** Opens the GitHub releases page in the browser. */
  openReleases(): Promise<void>;
  setKeyStorage(storage: KeySourceView): Promise<void>;
  /**
   * Unpairs every app paired with the other storage (server first, queued if
   * offline), then selects `storage` (§5). `removeCertificate`: switching to
   * the security chip also deletes the imported certificate.
   */
  switchKeyStorage(storage: KeySourceView, opts?: { removeCertificate?: boolean }): Promise<SwitchResultView>;
  /**
   * Opens the system file picker for a .p12 / .pfx. The main process keeps the
   * bytes; the page only gets an opaque token, valid for 5 minutes.
   */
  chooseCertificateFile(): Promise<CertificateFileResult | null>;
  inspectCertificate(input: { token: string; password: string }): Promise<CertificatePreviewResult>;
  /** Imports it and selects certificate key storage. */
  importCertificate(input: { token: string; password: string }): Promise<CertificateImportResult>;
  removeCertificate(id: string): Promise<CertificateRemoveResult>;
  /** Opens the system file picker for a PDF and checks it. null: cancelled. */
  chooseAndVerifyPdf(): Promise<VerifyResult | null>;
  /** Checks a PDF dropped on the window. Only its path reaches the main process, which reads and checks it. */
  verifyDroppedFile(file: File): Promise<VerifyResult>;
  /** Opens a checked file in the system's PDF viewer. */
  openVerifiedPdf(token: string): Promise<{ ok: boolean; error?: string }>;
  onStatusChanged(cb: () => void): () => void;
  onPairingProgress(cb: (p: PairingProgressView) => void): () => void;
  /** `certificate`: the agent is in certificate mode, so pair with the password screen (§3.1). */
  onPairPrefill(cb: (p: { origin: string; code: string; certificate: boolean }) => void): () => void;
  onJobState(cb: (s: JobState & { id: string }) => void): () => void;
  onUpdateChanged(cb: (u: UpdateView) => void): () => void;
  onVerifyRequested(cb: (e: VerifyRequestedEvent) => void): () => void;
  onVerifyFinished(cb: (e: VerifyFinishedEvent) => void): () => void;
}
