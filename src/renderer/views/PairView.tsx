import { useEffect, useState, type FormEvent } from 'react';

import type { PairingProgressView } from '../../shared/ipc';

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

export function PairView({ initialOrigin = '', initialCode = '', onDone }: Props) {
  const [origin, setOrigin] = useState(initialOrigin);
  const [code, setCode] = useState(initialCode);
  const [progress, setProgress] = useState<PairingProgressView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [pairedWith, setPairedWith] = useState<string | null>(null);

  useEffect(() => window.agent.onPairingProgress(setProgress), []);

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
    setError(null);
    setProgress(null);
    setRunning(true);
    const result = await window.agent.startPairing({ origin, code });
    setRunning(false);
    if (result.ok) setPairedWith(result.serverName);
    else setError(result.error);
  };

  if (pairedWith) {
    return (
      <main className="page">
        <section className="card center">
          <div className="big-check" aria-hidden="true">✓</div>
          <h1>Paired with {pairedWith}</h1>
          <p className="muted">You can now choose “Sign with this computer” in the web app.</p>
          <button type="button" className="button button-primary" onClick={onDone}>
            Done
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="page-header">
        <h1>Pair with an app</h1>
        <p className="muted">
          In the web app, open <strong>My signing devices</strong> and choose <strong>Pair desktop agent</strong>. Enter
          the address and code it shows, or paste the pairing link.
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
            A link asked to pair with <span className="mono">{initialOrigin}</span>. Only continue if that is the app you
            use.
          </p>
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

        {progress && running && <ProgressLine progress={progress} />}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <div className="actions">
          <button
            type="button"
            className="button button-quiet"
            onClick={() => (running ? void window.agent.cancelPairing() : onDone())}
          >
            Cancel
          </button>
          <button type="submit" className="button button-primary" disabled={running}>
            {running ? 'Pairing…' : 'Pair'}
          </button>
        </div>
      </form>
    </main>
  );
}

function ProgressLine({ progress }: { progress: PairingProgressView }) {
  switch (progress.stage) {
    case 'looking_up':
      return <p className="progress">Checking the code…</p>;
    case 'creating_keys':
      return <p className="progress">Creating this computer’s keys for {progress.serverName}. Approve the prompt if asked.</p>;
    case 'awaiting_confirmation':
      return (
        <p className="progress">
          Now confirm on the web: <strong>Pair “{progress.deviceLabel}”?</strong>
        </p>
      );
    default:
      return null;
  }
}
