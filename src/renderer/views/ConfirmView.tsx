import { useEffect, useState } from 'react';

import type { JobState, JobView } from '../../shared/ipc';
import { Icon } from '../icons';
import { currentPlatform, deviceTypeLabel, presenceLabel, protectionLabel } from '../labels';
import { AppHeader, Button, Hint, Notice, PasswordField, ResultView, displayOrigin } from '../ui';

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
  sign: { busy: 'Signing…', done: 'Signed', declined: 'Declined', nothing: 'Nothing was signed.', failed: 'Signing failed' },
  login: { busy: 'Signing in…', done: 'Signed in', declined: 'Denied', nothing: 'Nobody was signed in.', failed: 'Sign-in failed' },
};

// Confirm window for each job (desktop-agent-plan.md §7.4). This is UX: the
// OS prompt that follows Approve is what the key itself enforces.
export function ConfirmView({ jobId }: { jobId: string }) {
  const [job, setJob] = useState<JobView | null | undefined>(undefined);
  const [state, setState] = useState<JobState | null>(null);
  const armed = useArmedAfterFocus();
  // Certificate pairings approve with the certificate password (certificate-password-pairing-plan.md §4).
  const [password, setPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const waiting = useCountdown(retryAt);

  useEffect(() => {
    void window.agent.getJob(jobId).then(setJob);
    return window.agent.onJobState((s) => {
      if (s.id !== jobId) return;
      if (s.state === 'password_rejected') {
        // Ask again in this window; the job is still open on the server.
        setState(null);
        setPassword('');
        setPasswordError(s.error);
        setRetryAt(s.retryAt ? Date.parse(s.retryAt) : null);
        return;
      }
      setState(s);
    });
  }, [jobId]);

  if (job === undefined) return <main className="page" aria-busy="true" />;
  if (job === null) return <ResultView tone="neutral" title="Request expired" sub="Start again in the web app." />;

  const platform = currentPlatform();
  const words = job.login ? WORDS.login : WORDS.sign;
  const subject = `“${job.login ? job.serverName : job.documentTitle}”`;

  if (state) {
    switch (state.state) {
      case 'signing':
        return <ResultView tone="busy" title={words.busy} sub={subject} />;
      case 'waiting_for_os_prompt':
        return <ResultView tone="busy" title={`Approve with ${presenceLabel(platform, job.userPresence)}`} sub={subject} />;
      case 'completed':
        return <ResultView title={words.done} sub="Return to your browser." />;
      case 'rejected':
        return <ResultView tone="neutral" title={words.declined} sub={words.nothing} />;
      case 'failed':
        return (
          <ResultView tone="error" title={words.failed}>
            <Notice tone="error">{state.error}</Notice>
          </ResultView>
        );
    }
  }

  const decline = () => void window.agent.rejectJob(jobId);
  const needsPassword = job.passwordRequired;
  const canApprove = armed && (!needsPassword || (password !== '' && waiting === 0));
  // A pointer click only (detail > 0): Enter / Space typed into a
  // window that just took focus must never approve.
  const approve = (e: { detail: number }) => {
    if (e.detail <= 0 || !canApprove) return;
    if (needsPassword) {
      setPasswordError(null);
      void window.agent.approveJob(jobId, { password });
      setPassword('');
    } else {
      void window.agent.approveJob(jobId);
    }
  };
  const key = needsPassword
    ? null
    : `${protectionLabel(job.protection)} · ${presenceLabel(platform, job.userPresence)}`;

  const passwordField = needsPassword && (
    <>
      <PasswordField
        label="Certificate password"
        value={password}
        onChange={setPassword}
        disabled={waiting > 0}
        enterSubmits={false}
        autoFocus
      />
      {passwordError && (
        <Notice tone="error" role="alert">
          {waiting > 0 ? `${passwordError.replace(/ Try again in .*$/, '')} Try again in ${waiting} s.` : passwordError}
        </Notice>
      )}
    </>
  );

  const header = (
    <AppHeader
      eyebrow={job.login ? 'Sign-in request' : 'Signing request'}
      name={job.serverName}
      detail={<span className="mono">{displayOrigin(job.origin)}</span>}
    />
  );

  const actions = (
    <div className="actions-split">
      <Button size="block" icon="x" disabled={!armed} onClick={decline}>
        {job.login ? 'Deny' : 'Decline'}
      </Button>
      <Button
        size="block"
        variant="primary"
        icon={needsPassword ? (job.login ? 'check' : 'pen') : job.userPresence ? 'fingerprint' : 'check'}
        disabled={!canApprove}
        onClick={approve}
      >
        {needsPassword && !job.login ? 'Sign' : 'Approve'}
      </Button>
    </div>
  );

  if (job.login) {
    const code = job.login.matchCode;
    return (
      <main className="page">
        {header}
        <section className="card match-card">
          <div className="sub">Does your browser show this code?</div>
          {code.length <= 6 ? (
            <div className="match-code" aria-label={`Match code ${code.split('').join(' ')}`}>
              {code.split('').map((c, i) => (
                <span key={i} aria-hidden="true">
                  {c}
                </span>
              ))}
            </div>
          ) : (
            <div className="match-code-text">{code}</div>
          )}
        </section>

        <section className="card">
          <dl className="facts">
            {job.signerName && (
              <>
                <dt>Account</dt>
                <dd>
                  <strong>{job.signerName}</strong>
                </dd>
              </>
            )}
            <dt>Browser</dt>
            <dd>{job.login.browser || 'Unknown'}</dd>
            <dt>IP address</dt>
            <dd className="mono">{job.login.ip || 'Unknown'}</dd>
            <dt>Device</dt>
            <dd>{deviceTypeLabel(job.deviceType)}</dd>
            <dt>Key</dt>
            <dd>{key ?? 'Certificate password'}</dd>
          </dl>
        </section>

        {passwordField}
        <Hint>Only if the codes match and you just chose Sign in.</Hint>
        {actions}
      </main>
    );
  }

  return (
    <main className="page">
      {header}

      {job.transfer && (
        <Notice tone="info">
          Move <strong>{job.transfer.name}</strong>’s signature to {job.transfer.device}?
        </Notice>
      )}

      <section className="card">
        <div className="row row-top">
          <span className="tile tile-sm">
            <Icon name="document" size={20} />
          </span>
          <div className="grow">
            <div className="sub">{job.requestingApp ? `Requested by ${job.requestingApp}` : PURPOSES[job.purpose] ?? job.purpose}</div>
            <div className="document-title">{job.documentTitle}</div>
          </div>
        </div>
        <dl className="facts divider-top">
          <dt>Signer</dt>
          <dd>
            <strong>{job.signerName}</strong>
          </dd>
          {job.certificateName && (
            <>
              <dt>Certificate</dt>
              <dd>{job.certificateName}</dd>
            </>
          )}
          <dt>Device</dt>
          <dd>{deviceTypeLabel(job.deviceType)}</dd>
          {key && (
            <>
              <dt>Key</dt>
              <dd>{key}</dd>
            </>
          )}
        </dl>
      </section>

      {passwordField}
      <Hint>Only if you just started this in your browser.</Hint>
      {actions}
    </main>
  );
}

/** Seconds until `until` (a timestamp), ticking down; 0 once it has passed. */
function useCountdown(until: number | null): number {
  const left = () => (until ? Math.max(0, Math.ceil((until - Date.now()) / 1000)) : 0);
  const [seconds, setSeconds] = useState(left);
  useEffect(() => {
    setSeconds(left());
    if (!until) return;
    const timer = setInterval(() => {
      const next = left();
      setSeconds(next);
      if (next === 0) clearInterval(timer);
    }, 1000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [until]);
  return seconds;
}
