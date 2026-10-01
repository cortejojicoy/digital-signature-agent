import { useCallback, useEffect, useState } from 'react';

import type { StatusView as Status, UpdateView } from '../../shared/ipc';
import { IconButton } from '../icons';
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
  const dev = status.developerMode;

  return (
    <main className="page">
      <header className="page-header">
        <h1>Kukux Sign Agent</h1>
        <p className="muted">Version {status.version}</p>
      </header>

      <section className="card">
        <h2>This computer</h2>
        <dl className="facts">
          <dt>Key storage</dt>
          <dd>
            {caps.hardware ? (
              <span className="badge badge-strong">{status.platform === 'windows' ? 'TPM' : 'Secure Enclave'}</span>
            ) : (
              <span className="badge badge-weak">Software · lower assurance</span>
            )}
          </dd>
          <dt>Approval</dt>
          <dd>{caps.userPresence ? presenceLabel(status.platform, true) : 'Not available'}</dd>
          <dt>Attestation</dt>
          <dd>{caps.attestation ? 'Yes' : 'No'}</dd>
        </dl>
      </section>

      <section className="card">
        <div className="card-title-row">
          <h2>Paired apps</h2>
          <IconButton icon="plus" label="Pair with an app" variant="primary" onClick={onPair} />
        </div>
        {status.servers.length === 0 ? (
          <p className="muted">
            None yet. In the web app, open <strong>My signing devices → Pair desktop agent</strong>.
          </p>
        ) : (
          <ul className="server-list">
            {status.servers.map((s) => (
              <li key={s.id} className="server">
                <div>
                  <div className="server-name">
                    {s.name}
                    {s.insecure && <span className="badge badge-weak badge-inline">HTTP</span>}
                  </div>
                  <div className="mono muted">{s.origin}</div>
                  <div className="muted small">
                    {[s.deviceLabel, protectionLabel(s.protection), s.userName].filter(Boolean).join(' · ')}
                  </div>
                </div>
                <IconButton
                  icon="unlink"
                  label={busy === s.id ? 'Unpairing…' : 'Unpair'}
                  disabled={busy === s.id}
                  onClick={() => void unpair(s.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      <UpdatesCard />

      <section className="card">
        <label className="toggle-row">
          <span>
            <span className="toggle-title">Developer mode</span>
            <span className="muted small">
              {dev.locked ? 'Always on in npm run dev.' : 'Allow local-network apps over HTTP, for testing.'}
            </span>
          </span>
          <input
            type="checkbox"
            role="switch"
            className="switch"
            checked={dev.on}
            disabled={dev.locked}
            onChange={(e) => void window.agent.setDeveloperMode(e.target.checked).then(refresh)}
          />
        </label>
      </section>
    </main>
  );
}

function UpdatesCard() {
  const [update, setUpdate] = useState<UpdateView>({ state: 'idle' });

  useEffect(() => {
    void window.agent.getUpdate().then(setUpdate);
    return window.agent.onUpdateChanged(setUpdate);
  }, []);

  const checking = update.state === 'checking' || update.state === 'downloading';

  return (
    <section className="card" aria-live="polite">
      <div className="card-title-row">
        <h2>Updates</h2>
        <div className="button-row">
          <UpdateAction update={update} />
          <IconButton
            icon="refresh"
            label={checking ? 'Checking…' : 'Check for updates'}
            className={update.state === 'checking' ? 'is-spinning' : ''}
            disabled={checking || update.state === 'ready'}
            onClick={() => void window.agent.checkForUpdates()}
          />
        </div>
      </div>
      <UpdateSummary update={update} />
    </section>
  );
}

function UpdateAction({ update }: { update: UpdateView }) {
  const install = () => void window.agent.installUpdate();
  switch (update.state) {
    case 'available':
      return update.install === 'download' ? (
        <IconButton icon="download" label={`Download ${update.release.version}`} variant="primary" onClick={install} />
      ) : (
        <IconButton icon="external" label="Open download page" variant="primary" onClick={install} />
      );
    case 'ready':
      return <IconButton icon="restart" label="Restart to update" variant="primary" onClick={install} />;
    case 'error':
      return <IconButton icon="external" label="Open releases page" onClick={install} />;
    default:
      return null;
  }
}

function UpdateSummary({ update }: { update: UpdateView }) {
  switch (update.state) {
    case 'idle':
      return <p className="muted">Not checked yet.</p>;
    case 'checking':
      return <p className="muted">Checking GitHub…</p>;
    case 'up_to_date':
      return <p className="muted">Up to date · checked {formatTime(update.checkedAt)}</p>;
    case 'error':
      return (
        <p className="error" role="alert">
          {update.message}
        </p>
      );
    case 'downloading':
      return (
        <>
          <p className="muted">Downloading {update.release.version}… {update.percent}%</p>
          <progress className="progress-bar" max={100} value={update.percent} />
        </>
      );
    default: {
      const { release } = update;
      return (
        <div className="release">
          <p>
            <strong>{release.version} available</strong>
            {release.publishedAt && <span className="muted"> · {formatDate(release.publishedAt)}</span>}
            {update.state === 'ready' && <span className="muted"> · ready to install</span>}
          </p>
          {update.state === 'available' && update.install === 'open_page' && (
            <p className="muted small">Download it from the release page, then run the installer.</p>
          )}
          {release.notes && <p className="release-notes small">{release.notes}</p>}
        </div>
      );
    }
  }
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}
