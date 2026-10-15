// "Open in Kukux Sign Agent" in certificate mode (certificate-password-pairing-plan.md §1, §3):
// the address and code came in the link, so the screen shows what is about
// to be paired and asks only for the certificate's password.
import { useEffect, useState, type FormEvent } from 'react';

import type { PairingPreviewView, PairingProgressView, PairingResult } from '../../shared/ipc';
import { Icon } from '../icons';
import { AppHeader, Button, Hint, Notice, PageHeader, PasswordField, ResultView, Spinner } from '../ui';

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

  const failureNotice = failure && (
    <Notice
      tone="error"
      role="alert"
      actions={
        <>
          {failure.code === 'certificate_missing' && (
            <Button size="sm" variant="primary" icon="download" onClick={onImport}>
              Import certificate
            </Button>
          )}
          {(failure.code === 'account_already_paired' || failure.code === 'certificate_in_use') && failure.manageUrl && (
            <Button size="sm" icon="external" onClick={() => void window.agent.openDevicesPage()}>
              Open signing devices
            </Button>
          )}
        </>
      }
    >
      {failure.error}
    </Notice>
  );

  if (paired) {
    return (
      <ResultView
        title={`${paired.rebound ? 'Re-paired' : 'Paired'} with ${paired.serverName}`}
        sub="Return to your browser. Sign with your certificate password."
        onDone={onDone}
      />
    );
  }

  // Refused before any password: say why, offer the way out where there is one.
  if (!preview) {
    return (
      <main className="page">
        <PageHeader title={failure ? "Can't pair" : 'Checking…'} sub="Pair with certificate" />
        {failure ? failureNotice : <Spinner />}
        <div className="actions">
          <Button size="lg" icon="back" onClick={onDone}>
            Back
          </Button>
        </div>
      </main>
    );
  }

  return (
    <form className="page" onSubmit={(e) => void submit(e)}>
      <AppHeader
        eyebrow="Pair with certificate"
        name={preview.serverName}
        detail={
          <>
            <span className="mono">{preview.host}</span>
            {preview.userName ? ` · ${preview.userName}` : ''}
          </>
        }
      />

      <section className="card">
        <div className="inset-row">
          <span className="accent-icon">
            <Icon name="certificate" size={20} />
          </span>
          <span className="grow">
            <strong>{preview.certificateName}</strong>
          </span>
        </div>
        {preview.repair && <Notice tone="warning">Already paired with this certificate. Pairing again replaces it.</Notice>}

        <PasswordField label="Certificate password" value={password} onChange={setPassword} disabled={running} autoFocus />

        {running && (
          <div className="progress" role="status">
            <Spinner small />
            <span>
              {progress?.stage === 'awaiting_confirmation' ? `Confirm on ${preview.serverName} in your browser` : 'Pairing…'}
            </span>
          </div>
        )}
        {failureNotice}

        <Hint>Only if you just chose Pair this computer.</Hint>
      </section>

      <div className="actions">
        <Button size="lg" onClick={() => (running ? void window.agent.cancelPairing() : onDone())}>
          Cancel
        </Button>
        <Button type="submit" size="lg" variant="primary" icon="link" disabled={running || password === ''}>
          {running ? 'Pairing…' : 'Pair'}
        </Button>
      </div>
    </form>
  );
}
