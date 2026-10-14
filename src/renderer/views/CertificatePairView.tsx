// "Open in Kukux Sign Agent" in certificate mode (certificate-password-pairing-plan.md §1, §3):
// the address and code came in the link, so the screen shows what is about
// to be paired and asks only for the certificate's password.
import { useEffect, useState, type FormEvent } from 'react';

import type { PairingPreviewView, PairingProgressView, PairingResult } from '../../shared/ipc';
import { IconButton } from '../icons';

interface Props {
  origin: string;
  code: string;
  onDone: () => void;
  /** No certificate imported yet: import first, then come back here. */
  onImport: () => void;
}

type Failure = { error: string; code?: string; manageUrl?: string };

export function CertificatePairView({ origin, code, onDone, onImport }: Props) {
  const [preview, setPreview] = useState<PairingPreviewView | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<PairingProgressView | null>(null);
  const [paired, setPaired] = useState<Extract<PairingResult, { ok: true }> | null>(null);

  useEffect(() => window.agent.onPairingProgress(setProgress), []);
  useEffect(() => {
    let live = true;
    void window.agent.previewPairing({ origin, code }).then((result) => {
      if (!live) return;
      if (result.ok) setPreview(result.preview);
      else setFailure(result);
    });
    return () => {
      live = false;
    };
  }, [origin, code]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password || running) return;
    setFailure(null);
    setRunning(true);
    const result = await window.agent.startPairing({ origin, code, password });
    setRunning(false);
    setPassword('');
    if (result.ok) setPaired(result);
    else setFailure(result);
  };

  if (paired) {
    return (
      <main className="page">
        <section className="card center">
          <div className="big-check" aria-hidden="true">✓</div>
          <h1>
            {paired.rebound ? 'Re-paired' : 'Paired'} with {paired.serverName}
          </h1>
          <p className="muted">You'll use your certificate's password to sign. Go back to your browser to finish.</p>
          <IconButton icon="check" label="Done" variant="primary" tip="above" onClick={onDone} autoFocus />
        </section>
      </main>
    );
  }

  // Refused before any password: say why, offer the way out where there is one.
  if (!preview) {
    return (
      <main className="page">
        <header className="page-header">
          <p className="eyebrow">Pair with your certificate</p>
          <h1>{failure ? "Can't pair" : 'Checking…'}</h1>
        </header>
        {failure ? (
          <div className="error" role="alert">
            <p>{failure.error}</p>
            {failure.code === 'certificate_missing' && (
              <IconButton icon="download" label="Import certificate" variant="primary" tip="above" onClick={onImport} />
            )}
            {(failure.code === 'account_already_paired' || failure.code === 'certificate_in_use') && failure.manageUrl && (
              <IconButton icon="external" label="Open signing devices" tip="above" onClick={() => void window.agent.openDevicesPage()} />
            )}
          </div>
        ) : (
          <div className="spinner" aria-hidden="true" />
        )}
        <div className="actions">
          <IconButton icon="back" label="Back" tip="above" onClick={onDone} />
        </div>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="page-header">
        <p className="eyebrow">Pair with your certificate</p>
        <h1>{preview.serverName}</h1>
        <p className="mono muted">
          {preview.host}
          {preview.userName ? <span className="muted"> · for {preview.userName}</span> : null}
        </p>
      </header>

      <form className="card form" onSubmit={(e) => void submit(e)}>
        <dl className="facts">
          <dt>Certificate</dt>
          <dd>
            <strong>{preview.certificateName}</strong>
          </dd>
        </dl>
        {preview.repair && (
          <p className="warning small">
            {preview.serverName} is already paired with this certificate. Pairing again replaces it.
          </p>
        )}

        <label className="field">
          <span>Certificate password</span>
          <div className="password-row">
            <input
              type={show ? 'text' : 'password'}
              autoComplete="off"
              spellCheck={false}
              value={password}
              disabled={running}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
            />
            <IconButton
              icon={show ? 'eyeOff' : 'eye'}
              label={show ? 'Hide password' : 'Show password'}
              tip="above"
              onClick={() => setShow((v) => !v)}
            />
          </div>
        </label>

        {running && progress?.stage === 'awaiting_confirmation' && (
          <p className="progress">Confirm on {preview.serverName} in your browser.</p>
        )}
        {running && progress?.stage !== 'awaiting_confirmation' && <p className="progress">Pairing…</p>}
        {failure && (
          <div className="error" role="alert">
            <p>{failure.error}</p>
            {(failure.code === 'account_already_paired' || failure.code === 'certificate_in_use') && failure.manageUrl && (
              <IconButton icon="external" label="Open signing devices" tip="above" onClick={() => void window.agent.openDevicesPage()} />
            )}
          </div>
        )}

        <p className="muted small">Pair only if you just chose “Pair this computer” on {preview.serverName}.</p>

        <div className="actions">
          <IconButton
            icon={running ? 'x' : 'back'}
            label={running ? 'Cancel pairing' : 'Cancel'}
            tip="above"
            onClick={() => (running ? void window.agent.cancelPairing() : onDone())}
          />
          <IconButton
            type="submit"
            icon="check"
            label={running ? 'Pairing…' : 'Pair'}
            variant="primary"
            tip="above"
            disabled={running || password === ''}
          />
        </div>
      </form>
    </main>
  );
}
