// Signing jobs (desktop-agent-plan.md §8.3).
//
//   link → claim job from the paired server's stored origin → confirm window →
//   sign(identity key, canonical message) [Touch ID / Hello] → complete.
//
// The job's content comes from the server, never from the link, and it must
// belong to the user this machine was paired for. A login link claims a
// `login` job instead, then runs the same confirm, sign and complete.
import type { AgentApi, AgentJob, Credentials } from './api';
import { ApiError } from './api';
import { canonicalMessage } from './canonical';
import { isKeyStoreError, type KeyStore } from './keystore';
import { isUuid, type JobLink, type LoginLink } from './protocol';
import type { PairedServer, Store } from './store';

export type JobOutcome =
  | { result: 'completed'; jobId: string }
  | { result: 'rejected'; jobId: string; reason: string }
  | { result: 'ignored'; reason: string }
  | { result: 'failed'; jobId: string; error: string; code?: string };

export interface ConfirmRequest {
  job: AgentJob;
  server: PairedServer;
}

export interface JobDeps {
  keystore: KeyStore;
  store: Store;
  apiFor(server: PairedServer): AgentApi;
  credentialsFor(server: PairedServer): Credentials;
  /** Shows the confirm window; resolves true on Approve. UX only: the OS prompt is the security boundary. */
  confirm(request: ConfirmRequest): Promise<boolean>;
  /** Native handle of the window the OS prompt should be parented to. */
  parentWindow?(): Buffer | undefined;
  onUnauthorized?(server: PairedServer): void;
}

// `login` is not here: it only arrives through a login link (validateLogin).
const ALLOWED_PURPOSES = new Set(['sign_receipt', 'transfer']);
const MAX_TEXT = 300;
const MATCH_CODE = /^\d{2}-\d{2}$/;

export class JobRunner {
  private queue: Promise<unknown> = Promise.resolve();
  private readonly active = new Set<string>();

  constructor(private readonly deps: JobDeps) {}

  /** Jobs run one at a time, so only one confirm window / OS prompt is up. */
  handle(link: JobLink): Promise<JobOutcome> {
    return this.enqueue(link.jobId, () => this.run(link));
  }

  /** A sign-in runs in the same queue as jobs. */
  handleLogin(link: LoginLink): Promise<JobOutcome> {
    return this.enqueue(link.challengeId, () => this.runLogin(link));
  }

  private enqueue(id: string, task: () => Promise<JobOutcome>): Promise<JobOutcome> {
    if (this.active.has(id)) return Promise.resolve({ result: 'ignored', reason: 'already in progress' });
    this.active.add(id);
    const run = this.queue.then(task).finally(() => this.active.delete(id));
    this.queue = run.catch(() => {});
    return run;
  }

  private async run(link: JobLink): Promise<JobOutcome> {
    const server = this.deps.store.get(link.serverId);
    if (!server) return { result: 'ignored', reason: 'unknown server' };

    let job: AgentJob;
    let api: AgentApi;
    let creds: Credentials;
    try {
      api = this.deps.apiFor(server);
      creds = this.deps.credentialsFor(server);
      job = await api.claimJob(creds, link.jobId, link.token);
    } catch (err) {
      if (err instanceof ApiError && err.unauthorized) this.deps.onUnauthorized?.(server);
      return failure(link.jobId, err);
    }

    const problem = validateJob(job, link, server);
    if (problem) {
      await api.rejectJob(creds, link.jobId, 'invalid_job').catch(() => {});
      return { result: 'failed', jobId: link.jobId, error: problem };
    }
    return this.confirmAndSign(api, creds, job, server);
  }

  private async runLogin(link: LoginLink): Promise<JobOutcome> {
    // Unlike a job link, the user is waiting on this: say why nothing happens.
    const server = this.deps.store.get(link.serverId);
    if (!server) return { result: 'failed', jobId: link.challengeId, error: NOT_PAIRED, code: 'not_paired' };

    let job: AgentJob;
    let api: AgentApi;
    let creds: Credentials;
    try {
      api = this.deps.apiFor(server);
      creds = this.deps.credentialsFor(server);
      job = await api.claimLogin(creds, link.challengeId, link.token);
    } catch (err) {
      if (err instanceof ApiError && err.unauthorized) this.deps.onUnauthorized?.(server);
      return failure(link.challengeId, err);
    }

    const problem = validateLogin(job, server);
    if (problem) {
      if (isUuid(job?.uuid)) await api.rejectJob(creds, job.uuid, 'invalid_job').catch(() => {});
      return { result: 'failed', jobId: link.challengeId, error: problem };
    }
    return this.confirmAndSign(api, creds, job, server);
  }

  private async confirmAndSign(api: AgentApi, creds: Credentials, job: AgentJob, server: PairedServer): Promise<JobOutcome> {
    const approved = await this.deps.confirm({ job, server });
    if (!approved) {
      await api.rejectJob(creds, job.uuid, 'declined').catch(() => {});
      return { result: 'rejected', jobId: job.uuid, reason: 'declined' };
    }

    const message = canonicalMessage(job.purpose, job.nonce, job.user_id, job.payload_hash);
    let signature: Buffer;
    try {
      signature = await this.deps.keystore.sign(
        server.identityKeyId,
        Buffer.from(message, 'utf8'),
        promptReason(job, server),
        this.deps.parentWindow?.(),
      );
    } catch (err) {
      if (isKeyStoreError(err, 'E_CANCELLED')) {
        await api.rejectJob(creds, job.uuid, 'os_prompt_cancelled').catch(() => {});
        return { result: 'rejected', jobId: job.uuid, reason: 'os_prompt_cancelled' };
      }
      return failure(job.uuid, err);
    }

    try {
      await api.completeJob(creds, job.uuid, signature.toString('base64'));
    } catch (err) {
      return failure(job.uuid, err);
    }
    return { result: 'completed', jobId: job.uuid };
  }
}

const NOT_PAIRED =
  "This computer isn't paired with the app you're signing in to. Pair it first: open the website and choose Pair this computer.";

/** What the Touch ID / Hello prompt says the key is for. */
function promptReason(job: AgentJob, server: PairedServer): string {
  if (job.purpose === 'login') return `sign in to ${server.name} (code ${job.login!.match_code})`;
  if (job.purpose === 'transfer') return `move ${job.transfer!.name}'s signature to ${job.transfer!.device}`;
  return `sign "${job.document.title}" as ${job.signer.name}`;
}

export function validateJob(job: AgentJob, link: JobLink, server: PairedServer): string | null {
  if (!job || typeof job !== 'object') return 'the server sent an invalid job';
  if (job.uuid !== link.jobId) return 'the job id does not match the link';
  if (!ALLOWED_PURPOSES.has(job.purpose)) return `unsupported purpose: ${String(job.purpose)}`;
  if (String(job.user_id) !== server.userId) return 'the job belongs to a different user';
  if (!isText(job.document?.title) || !isText(job.signer?.name)) return 'the job is missing its document or signer';
  if (job.purpose === 'transfer' && (!isText(job.transfer?.name) || !isText(job.transfer?.device))) {
    return 'the transfer is missing its name or computer';
  }
  return commonProblem(job);
}

/**
 * A claimed sign-in. The job id comes from the server (the link carries the
 * challenge id), so it is checked here instead of against the link. The
 * signer's name may be empty: a hub account has none until it identifies.
 */
export function validateLogin(job: AgentJob, server: PairedServer): string | null {
  if (!job || typeof job !== 'object') return 'the server sent an invalid sign-in';
  if (!isUuid(job.uuid)) return 'the server sent an invalid sign-in id';
  if (job.purpose !== 'login') return `unsupported purpose: ${String(job.purpose)}`;
  if (String(job.user_id) !== server.userId) return 'the sign-in belongs to a different user';
  if (!isText(job.document?.title) || !isOptionalText(job.signer?.name)) return 'the sign-in is missing its title';
  const login = job.login;
  if (typeof login?.match_code !== 'string' || !MATCH_CODE.test(login.match_code)) return 'the sign-in has no valid match code';
  if (!isOptionalText(login.browser) || !isOptionalText(login.ip)) return 'the sign-in has an invalid browser or address';
  return commonProblem(job);
}

/** Checks every job shares: the optional requesting app, and a buildable canonical message. */
function commonProblem(job: AgentJob): string | null {
  if (job.requesting_app != null && !isText(job.requesting_app.name)) return 'the job names an invalid requesting app';
  try {
    canonicalMessage(job.purpose, job.nonce, job.user_id, job.payload_hash);
  } catch (err) {
    return describe(err);
  }
  return null;
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= MAX_TEXT;
}

/** Absent, empty, or text within the limit: for display-only fields. */
function isOptionalText(value: unknown): boolean {
  return value == null || (typeof value === 'string' && value.length <= MAX_TEXT);
}

function failure(jobId: string, err: unknown): JobOutcome {
  const code = err instanceof ApiError ? (err.outdated ? 'agent_outdated' : err.code) : undefined;
  return { result: 'failed', jobId, error: describe(err), code };
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
