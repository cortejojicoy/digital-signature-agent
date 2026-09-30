import { useCallback, useEffect, useState } from 'react';

import type { StatusView as Status } from '../../shared/ipc';
import { presenceLabel, protectionLabel } from '../labels';

export function StatusView({ onPair }: { onPair: () => void }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(() => {
    void window.agent.getStatus().then(setStatus);
  }, []);

  useEffect(() => {
    refresh();
    return window.agent.onStatusChanged(refresh);
  }, [refresh]);

  if (!status) return <main className="page" aria-busy="true" />;

  const unpair = async (id: string) => {
    setBusy(id);
    try {
      await window.agent.unpair(id);
    } finally {
      setBusy(null);
      refresh();
    }
  };

  const caps = status.capabilities;

  return (
    <main className="page">
      <header className="page-header">
        <h1>Kukux Sign Agent</h1>
        <p className="muted">Version {status.version}</p>
      </header>

      <section className="card">
        <h2>This computer</h2>
        <dl className="facts">
          <dt>Key protection</dt>
          <dd>
            {caps.hardware ? (
              <span className="badge badge-strong">{status.platform === 'windows' ? 'TPM' : 'Secure Enclave'}</span>
            ) : (
              <span className="badge badge-weak">Software key · lower assurance</span>
            )}
          </dd>
          <dt>Approval on each use</dt>
          <dd>{caps.userPresence ? presenceLabel(status.platform, true) : 'Not available'}</dd>
          <dt>Attestation</dt>
          <dd>{caps.attestation ? 'Available' : 'Not available'}</dd>
        </dl>
      </section>

      <section className="card">
        <div className="card-title-row">
          <h2>Paired apps</h2>
          <button type="button" className="button button-primary" onClick={onPair}>
            Pair with an app
          </button>
        </div>
        {status.servers.length === 0 ? (
          <p className="muted">
            Not paired yet. In the web app, open <strong>My signing devices</strong> and choose{' '}
            <strong>Pair desktop agent</strong>.
          </p>
        ) : (
          <ul className="server-list">
            {status.servers.map((s) => (
              <li key={s.id} className="server">
                <div>
                  <div className="server-name">{s.name}</div>
                  <div className="mono muted">{s.origin}</div>
                  <div className="muted small">
                    {s.deviceLabel} · {protectionLabel(s.protection)} · {presenceLabel(status.platform, s.userPresence)}
                    {s.userName ? ` · ${s.userName}` : ''}
                  </div>
                </div>
                <button
                  type="button"
                  className="button button-quiet"
                  disabled={busy === s.id}
                  onClick={() => void unpair(s.id)}
                >
                  {busy === s.id ? 'Unpairing…' : 'Unpair'}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
