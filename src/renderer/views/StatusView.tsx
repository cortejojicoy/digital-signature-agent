import { useCallback, useEffect, useState } from 'react';

import type { StatusView as Status, UpdateView } from '../../shared/ipc';
import { IconButton, type IconName } from '../icons';
import { deviceTypeLabel, presenceLabel, protectionLabel } from '../labels';
import { OfflinePrompt, useUnpair } from '../unpair';
import { AboutDialog } from './AboutDialog';

export function StatusView({ onPair }: { onPair: () => void }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [retrying, setRetrying] = useState<string | null>(null);

  const refresh = useCallback(() => {
    void window.agent.getStatus().then(setStatus);
  }, []);
  const unpairing = useUnpair(refresh);

  useEffect(() => {
    refresh();
    return window.agent.onStatusChanged(refresh);
  }, [refresh]);

  if (!status) return <main className="page" aria-busy="true" />;

  const retry = async (origin: string) => {
    setRetrying(origin);
    try {
      await window.agent.retryRevokes(origin);
    } finally {
      setRetrying(null);
      refresh();
    }
  };

  const caps = status.capabilities;
  const dev = status.developerMode;

  return (
    <main className="page">
      <header className="page-header">
        <h1>Kukux Sign Agent</h1>
        <VersionRow version={status.version} platform={status.platform} capabilities={status.capabilities} />
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
        <p className="muted small">
          One signature per app on this computer, and one computer per account. To use another account for an app, unpair
          it first.
        </p>
        {unpairing.note && (
          <p className="muted small" role="status">
            {unpairing.note}
          </p>
        )}
        {status.servers.length === 0 ? (
          <p className="muted">
            None yet. Open the website (<span className="mono">signature.uplb.edu.ph</span> for UPLB) and choose{' '}
            <strong>Pair this computer</strong>.
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
                    {[s.userName, s.deviceLabel, deviceTypeLabel(s.deviceType), protectionLabel(s.protection)]
                      .filter(Boolean)
                      .join(' · ')}
                  </div>
                  {s.otherDevices.length > 0 && (
                    <details className="other-devices small">
                      <summary className="muted">
                        Also paired on {s.otherDevices.length} other {s.otherDevices.length === 1 ? 'device' : 'devices'}
                      </summary>
                      <ul>
                        {s.otherDevices.map((d, i) => (
                          <li key={i} className="muted">
                            {d.label}
                            {d.deviceType ? ` · ${deviceTypeLabel(d.deviceType)}` : ''}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                  {unpairing.offline?.serverId === s.id && (
                    <OfflinePrompt
                      serverName={unpairing.offline.serverName}
                      busy={unpairing.busy === s.id}
                      onRemove={() => void unpairing.removeAnyway()}
                      onKeep={unpairing.keep}
                    />
                  )}
                </div>
                <IconButton
                  icon="unlink"
                  label={unpairing.busy === s.id ? 'Unpairing…' : 'Unpair'}
                  disabled={unpairing.busy === s.id || unpairing.offline?.serverId === s.id}
                  onClick={() => void unpairing.unpair(s.id)}
                />
              </li>
            ))}
          </ul>
        )}
        {status.pendingRevokes.length > 0 && (
          <ul className="server-list">
            {status.pendingRevokes.map((r) => (
              <li key={`${r.origin}|${r.queuedAt}`} className="server">
                <div>
                  <div className="server-name">Waiting to tell {r.serverName}</div>
                  <div className="mono muted">{r.origin}</div>
                  <div className="muted small">
                    Removed from this computer on {formatWhen(r.queuedAt)}. Until {r.serverName} hears, it still lists this
                    computer, so your account can't pair another one. Retried every hour.
                  </div>
                </div>
                <IconButton
                  icon="refresh"
                  label={retrying === r.origin ? 'Retrying…' : 'Retry now'}
                  className={retrying === r.origin ? 'is-spinning' : ''}
                  disabled={retrying === r.origin}
                  onClick={() => void retry(r.origin)}
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
function VersionRow({
  version,
  platform,
  capabilities,
}: {
  version: string;
  platform: Status['platform'];
  capabilities: Status['capabilities'];
}) {
  const [update, setUpdate] = useState<UpdateView>({ state: 'idle' });
  const [showNotes, setShowNotes] = useState(false);
  const closeNotes = useCallback(() => setShowNotes(false), []);

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
      <button type="button" className="version-link" title="About this app" onClick={() => setShowNotes(true)}>
        Version {version}
      </button>
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
      {showNotes && (
        <AboutDialog version={version} platform={platform} capabilities={capabilities} update={update} onClose={closeNotes} />
      )}
    </div>
  );
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}
