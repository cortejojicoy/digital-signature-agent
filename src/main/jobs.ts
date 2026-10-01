// Signing jobs (desktop-agent-plan.md §8.3).
//
//   link → claim job from the paired server's stored origin → confirm window →
//   sign(identity key, canonical message) [Touch ID / Hello] → complete.
//
// The job's content comes from the server, never from the link, and it must
// belong to the user this machine was paired for.
import type { AgentApi, AgentJob, Credentials } from './api';
import { ApiError } from './api';
import { canonicalMessage } from './canonical';
import { isKeyStoreError, type KeyStore } from './keystore';
import type { JobLink } from './protocol';
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

const ALLOWED_PURPOSES = new Set(['sign_receipt']);
const MAX_TEXT = 300;

export class JobRunner {
  private queue: Promise<unknown> = Promise.resolve();
  private readonly active = new Set<string>();

  constructor(private readonly deps: JobDeps) {}

  /** Jobs run one at a time, so only one confirm window / OS prompt is up. */
  handle(link: JobLink): Promise<JobOutcome> {
    if (this.active.has(link.jobId)) return Promise.resolve({ result: 'ignored', reason: 'already in progress' });
    this.active.add(link.jobId);
    const run = this.queue.then(() => this.run(link)).finally(() => this.active.delete(link.jobId));
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
        `sign "${job.document.title}" as ${job.signer.name}`,
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

export function validateJob(job: AgentJob, link: JobLink, server: PairedServer): string | null {
  if (!job || typeof job !== 'object') return 'the server sent an invalid job';
  if (job.uuid !== link.jobId) return 'the job id does not match the link';
  if (!ALLOWED_PURPOSES.has(job.purpose)) return `unsupported purpose: ${String(job.purpose)}`;
  if (String(job.user_id) !== server.userId) return 'the job belongs to a different user';
  if (!isText(job.document?.title) || !isText(job.signer?.name)) return 'the job is missing its document or signer';
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

function failure(jobId: string, err: unknown): JobOutcome {
  const code = err instanceof ApiError ? (err.outdated ? 'agent_outdated' : err.code) : undefined;
  return { result: 'failed', jobId, error: describe(err), code };
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
