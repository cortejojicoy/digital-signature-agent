import { useCallback, useEffect, useState } from 'react';

import type { StatusView as Status, UpdateView } from '../../shared/ipc';
import { IconButton, type IconName } from '../icons';
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
        <VersionRow version={status.version} />
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

// The version line doubles as the update control: one small icon that turns
// into Download / Restart when there's an update, and a short status word.
function VersionRow({ version }: { version: string }) {
  const [update, setUpdate] = useState<UpdateView>({ state: 'idle' });

  useEffect(() => {
    void window.agent.getUpdate().then(setUpdate);
    return window.agent.onUpdateChanged(setUpdate);
  }, []);

  const check = () => void window.agent.checkForUpdates();
  const install = () => void window.agent.installUpdate();
  const busy = update.state === 'checking' || update.state === 'downloading';

  let note: string | null = null;
  let button: {
    icon: IconName;
    label: string;
    onClick: () => void;
    accent?: boolean;
  };
  switch (update.state) {
    case 'available':
      note = `${update.release.version} available`;
      button =
        update.install === 'download'
          ? {
              icon: 'download',
              label: `Download ${update.release.version}`,
              onClick: install,
              accent: true,
            }
          : {
              icon: 'external',
              label: 'Open download page',
              onClick: install,
              accent: true,
            };
      break;
    case 'downloading':
      note = `Downloading ${update.percent}%`;
      button = { icon: 'refresh', label: 'Downloading…', onClick: check };
      break;
    case 'ready':
      note = `${update.release.version} ready`;
      button = {
        icon: 'restart',
        label: 'Restart to update',
        onClick: install,
        accent: true,
      };
      break;
    case 'checking':
      button = { icon: 'refresh', label: 'Checking…', onClick: check };
      break;
    case 'up_to_date':
      note = 'Up to date';
      button = {
        icon: 'refresh',
        label: `Checked ${formatTime(update.checkedAt)} · check again`,
        onClick: check,
      };
      break;
    case 'error':
      note = 'Update check failed';
      button = { icon: 'refresh', label: 'Try again', onClick: check };
      break;
    default:
      button = { icon: 'refresh', label: 'Check for updates', onClick: check };
  }

  return (
    <div className="version-row" aria-live="polite">
      <span className="muted">Version {version}</span>
      {note && (
        <span
          className={update.state === 'error' ? 'error small' : button.accent ? 'accent small' : 'muted small'}
          title={update.state === 'error' ? update.message : undefined}
        >
          · {note}
        </span>
      )}
      <IconButton
        icon={button.icon}
        label={button.label}
        size="small"
        tipAlign="start"
        className={`${update.state === 'checking' || update.state === 'downloading' ? 'is-spinning' : ''} ${button.accent ? 'is-accent' : ''}`}
        disabled={busy}
        onClick={button.onClick}
      />
    </div>
  );
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}
