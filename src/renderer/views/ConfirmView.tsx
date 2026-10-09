import { useEffect, useState } from 'react';

import type { JobState, JobView } from '../../shared/ipc';
import { Icon } from '../icons';
import { currentPlatform, deviceTypeLabel, presenceLabel, protectionLabel } from '../labels';

const ARM_DELAY_MS = 1000;

// The window pops up over whatever the user is doing. Like browser permission
// prompts, ignore input until it has been visible and focused for a moment,
// so a click or keystroke meant for another app can't land on Approve.
function useArmedAfterFocus(): boolean {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = () => {
      setArmed(false);
      clearTimeout(timer);
      timer = setTimeout(() => setArmed(true), ARM_DELAY_MS);
    };
    const disarm = () => {
      clearTimeout(timer);
      setArmed(false);
    };
    if (document.hasFocus()) arm();
    window.addEventListener('focus', arm);
    window.addEventListener('blur', disarm);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('focus', arm);
      window.removeEventListener('blur', disarm);
    };
  }, []);
  return armed;
}

const PURPOSES: Record<string, string> = {
  sign_receipt: 'Sign a document',
  transfer: 'Move your signature',
};

// What the finished states say, per purpose.
const WORDS = {
  sign: { waiting: 'Signing', done: 'Signed', declined: 'Declined', nothing: 'Nothing was signed.', failed: 'Signing failed' },
  login: { waiting: 'Signing in to', done: 'Signed in', declined: 'Denied', nothing: 'Nobody was signed in.', failed: 'Sign-in failed' },
};

// Confirm window for each job (desktop-agent-plan.md §7.4). This is UX: the
// OS prompt that follows Approve is what the key itself enforces.
export function ConfirmView({ jobId }: { jobId: string }) {
  const [job, setJob] = useState<JobView | null | undefined>(undefined);
  const [state, setState] = useState<JobState | null>(null);
  const armed = useArmedAfterFocus();

  useEffect(() => {
    void window.agent.getJob(jobId).then(setJob);
    return window.agent.onJobState((s) => {
      if (s.id === jobId) setState(s);
    });
  }, [jobId]);

  if (job === undefined) return <main className="page" aria-busy="true" />;
  if (job === null) {
    return (
      <main className="page">
        <section className="card center">
          <h1>Request expired</h1>
          <p className="muted">Start again in the web app.</p>
        </section>
      </main>
    );
  }

  const platform = currentPlatform();
  const words = job.login ? WORDS.login : WORDS.sign;

  if (state) {
    return (
      <main className="page">
        <section className="card center" aria-live="polite">
          {state.state === 'waiting_for_os_prompt' && (
            <>
              <div className="spinner" aria-hidden="true" />
              <h1>Approve with {presenceLabel(platform, job.userPresence)}</h1>
              <p className="muted">
                {words.waiting} “{job.login ? job.serverName : job.documentTitle}”
              </p>
            </>
          )}
          {state.state === 'completed' && (
            <>
              <div className="big-check" aria-hidden="true">✓</div>
              <h1>{words.done}</h1>
              <p className="muted">Return to your browser.</p>
            </>
          )}
          {state.state === 'rejected' && (
            <>
              <h1>{words.declined}</h1>
              <p className="muted">{words.nothing}</p>
            </>
          )}
          {state.state === 'failed' && (
            <>
              <h1>{words.failed}</h1>
              <p className="error">{state.error}</p>
            </>
          )}
        </section>
      </main>
    );
  }

  const decline = () => void window.agent.rejectJob(jobId);
  // A pointer click only (detail > 0): Enter / Space typed into a
  // window that just took focus must never approve.
  const approve = (e: { detail: number }) => {
    if (e.detail > 0) void window.agent.approveJob(jobId);
  };

  if (job.login) {
    return (
      <main className="page">
        <header className="page-header">
          <p className="eyebrow">Sign-in request from</p>
          <h1>{job.serverName}</h1>
          <p className="mono muted">{job.origin}</p>
        </header>

        <section className="card center">
          <h1>
            Does your browser show <span className="match-code">{job.login.matchCode}</span>?
          </h1>
          <p className="lead muted">{job.documentTitle}</p>
        </section>

        <section className="card">
          <dl className="facts">
            <dt>Browser</dt>
            <dd>{job.login.browser || 'Unknown'}</dd>
            <dt>Address</dt>
            <dd className="mono">{job.login.ip || 'Unknown'}</dd>
            {job.signerName && (
              <>
                <dt>Signing in as</dt>
                <dd>{job.signerName}</dd>
              </>
            )}
            <dt>Key</dt>
            <dd>
              {deviceTypeLabel(job.deviceType)} · {protectionLabel(job.protection)} · {presenceLabel(platform, job.userPresence)}
            </dd>
          </dl>
        </section>

        <p className="muted small">Approve only if the code matches and you just chose Sign in in your browser.</p>

        <div className="actions">
          <button type="button" className="button button-quiet button-icon" disabled={!armed} onClick={decline}>
            <Icon name="x" />
            Deny
          </button>
          <button type="button" className="button button-primary button-icon" disabled={!armed} onClick={approve}>
            <Icon name="check" />
            Approve
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="page-header">
        <p className="eyebrow">Signing request from</p>
        <h1>{job.serverName}</h1>
        <p className="mono muted">{job.origin}</p>
      </header>

      {job.transfer && (
        <p className="lead">
          Move <strong>{job.transfer.name}</strong>’s signature to a new computer ({job.transfer.device})?
        </p>
      )}
      {job.requestingApp && (
        <p className="lead">
          <strong>{job.requestingApp}</strong> asks: {job.documentTitle}
        </p>
      )}

      <section className="card">
        <dl className="facts">
          <dt>Document</dt>
          <dd className="document-title">{job.documentTitle}</dd>
          <dt>Signing as</dt>
          <dd>{job.signerName}</dd>
          <dt>Action</dt>
          <dd>{PURPOSES[job.purpose] ?? job.purpose}</dd>
          <dt>Key</dt>
          <dd>
            {deviceTypeLabel(job.deviceType)} · {protectionLabel(job.protection)} · {presenceLabel(platform, job.userPresence)}
          </dd>
        </dl>
      </section>

      <p className="muted small">Approve only if you just started this in your browser.</p>

      <div className="actions">
        <button type="button" className="button button-quiet button-icon" disabled={!armed} onClick={decline}>
          <Icon name="x" />
          Decline
        </button>
        <button type="button" className="button button-primary button-icon" disabled={!armed} onClick={approve}>
          <Icon name="check" />
          Approve
        </button>
      </div>
    </main>
  );
}
