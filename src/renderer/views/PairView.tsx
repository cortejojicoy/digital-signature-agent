import { useEffect, useState, type FormEvent } from 'react';

import type { PairingProgressView, PairingResult, ServerView } from '../../shared/ipc';
import { IconButton } from '../icons';

interface Props {
  initialOrigin?: string;
  initialCode?: string;
  onDone: () => void;
}

// A pasted kukuxsign://pair?o=…&c=… link fills both fields. The main process
// validates everything again; this is only a convenience.
function fromPastedLink(text: string): { origin: string; code: string } | null {
  try {
    const url = new URL(text.trim());
    if (url.protocol !== 'kukuxsign:' || url.host !== 'pair') return null;
    return { origin: url.searchParams.get('o') ?? '', code: url.searchParams.get('c') ?? '' };
  } catch {
    return null;
  }
}

// Loose match for the "already paired" notice only; the main process decides.
function sameOrigin(a: string, b: string): boolean {
  const norm = (v: string) => v.trim().toLowerCase().replace(/\/+$/, '');
  return norm(a) !== '' && norm(a) === norm(b);
}

type Failure = Extract<PairingResult, { ok: false }>;

export function PairView({ initialOrigin = '', initialCode = '', onDone }: Props) {
  const [origin, setOrigin] = useState(initialOrigin);
  const [code, setCode] = useState(initialCode);
  const [progress, setProgress] = useState<PairingProgressView | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [running, setRunning] = useState(false);
  const [paired, setPaired] = useState<{ serverName: string; rebound: boolean } | null>(null);
  const [servers, setServers] = useState<ServerView[]>([]);
  const [unpairing, setUnpairing] = useState(false);

  useEffect(() => window.agent.onPairingProgress(setProgress), []);
  useEffect(() => {
    const load = () => void window.agent.getStatus().then((s) => setServers(s.servers));
    load();
    return window.agent.onStatusChanged(load);
  }, []);

  // One signature per app on this computer: say so before the user submits.
  const holder = servers.find((s) => sameOrigin(s.origin, origin));

  const unpair = async (serverId: string) => {
    setUnpairing(true);
    try {
      await window.agent.unpair(serverId);
      setFailure(null);
    } finally {
      setUnpairing(false);
    }
  };

  const applyPaste = (value: string, set: (v: string) => void) => {
    const link = fromPastedLink(value);
    if (link) {
      setOrigin(link.origin);
      setCode(link.code);
    } else {
      set(value);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setFailure(null);
    setProgress(null);
    setRunning(true);
    const result = await window.agent.startPairing({ origin, code });
    setRunning(false);
    if (result.ok) setPaired({ serverName: result.serverName, rebound: result.rebound });
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
          {paired.rebound && <p className="muted">Your existing device was updated with new keys.</p>}
          <p className="muted">Choose “Sign with this computer” in the web app.</p>
          <IconButton icon="check" label="Done" variant="primary" tip="above" onClick={onDone} autoFocus />
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="page-header">
        <h1>Pair with an app</h1>
        <p className="muted">
          Enter the address and code from <strong>My signing devices → Pair desktop agent</strong>, or paste the pairing
          link.
        </p>
      </header>

      <form className="card form" onSubmit={(e) => void submit(e)}>
        <label className="field">
          <span>App address</span>
          <input
            className="mono"
            type="text"
            inputMode="url"
            placeholder="https://sign.example.gov.ph"
            value={origin}
            disabled={running}
            onChange={(e) => applyPaste(e.target.value, setOrigin)}
            autoFocus={!initialOrigin}
            required
          />
        </label>
        {initialOrigin && (
          <p className="warning small">
            Opened from a link. Continue only if you use <span className="mono">{initialOrigin}</span>.
          </p>
        )}
        {holder && !running && (
          <div className="warning small">
            <p>
              This computer already holds {holder.userName ? `${holder.userName}'s` : 'a'} signature for {holder.name}. Unpair
              it to use a different account, or continue to re-pair {holder.userName ? `${holder.userName}'s` : 'it'}.
            </p>
            <IconButton
              icon="unlink"
              label={unpairing ? 'Unpairing…' : `Unpair ${holder.name}`}
              tip="above"
              disabled={unpairing}
              onClick={() => void unpair(holder.id)}
            />
          </div>
        )}
        <label className="field">
          <span>Pairing code</span>
          <input
            className="mono code-input"
            type="text"
            placeholder="K7QM-2XPD"
            maxLength={64}
            value={code}
            disabled={running}
            onChange={(e) => applyPaste(e.target.value, setCode)}
            autoFocus={!!initialOrigin}
            required
          />
        </label>

        {progress && running && progress.stage === 'already_paired_locally' ? (
          <div className="warning small" role="alertdialog" aria-label="Already paired">
            <p>
              Your {progress.serverName} signature is already on this computer
              {progress.userName ? ` (${progress.userName})` : ''}. Re-pair it with new keys?
            </p>
            <div className="actions">
              <IconButton icon="x" label="Keep the current pairing" tip="above" onClick={() => void window.agent.confirmRepair(false)} />
              <IconButton
                icon="refresh"
                label="Re-pair with new keys"
                variant="primary"
                tip="above"
                onClick={() => void window.agent.confirmRepair(true)}
              />
            </div>
          </div>
        ) : (
          progress && running && <ProgressLine progress={progress} />
        )}
        {failure && (
          <div className="error" role="alert">
            <p>{failure.error}</p>
            {failure.code === 'app_already_paired' && failure.serverId && (
              <IconButton
                icon="unlink"
                label={unpairing ? 'Unpairing…' : `Unpair ${failure.serverName ?? 'that app'}`}
                tip="above"
                disabled={unpairing}
                onClick={() => void unpair(failure.serverId!)}
              />
            )}
          </div>
        )}

        <div className="actions">
          <IconButton
            icon={running ? 'x' : 'back'}
            label={running ? 'Cancel pairing' : 'Back'}
            tip="above"
            onClick={() => (running ? void window.agent.cancelPairing() : onDone())}
          />
          <IconButton type="submit" icon="check" label={running ? 'Pairing…' : 'Pair'} variant="primary" tip="above" disabled={running} />
        </div>
      </form>
    </main>
  );
}

function ProgressLine({ progress }: { progress: PairingProgressView }) {
  switch (progress.stage) {
    case 'looking_up':
      return <p className="progress">Checking code…</p>;
    case 'creating_keys':
      return <p className="progress">Creating keys for {progress.serverName}. Approve the prompt.</p>;
    case 'awaiting_confirmation':
      return (
        <p className="progress">
          {progress.existingDevice ? (
            <>
              Updating your existing device <strong>“{progress.existingDevice.label}”</strong>. Confirm in the web app.
            </>
          ) : (
            <>
              Confirm <strong>“{progress.deviceLabel}”</strong> in the web app.
            </>
          )}
        </p>
      );
    default:
      return null;
  }
}
