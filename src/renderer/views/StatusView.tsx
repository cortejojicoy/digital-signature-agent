import { useCallback, useEffect, useState } from 'react';

import type { CertificateView, KeySourceView, StatusView as Status, UpdateView } from '../../shared/ipc';
import { IconButton, type IconName } from '../icons';
import { deviceTypeLabel, formatDate, keyStorageLabel, pairingKeyLabel, presenceLabel } from '../labels';
import { OfflinePrompt, useUnpair } from '../unpair';
import { AboutDialog } from './AboutDialog';
import { KeyStorageView } from './KeyStorageView';

interface Props {
  onPair: () => void;
  /** Change next to Key storage (pkcs12-key-storage-plan.md §7.3). */
  onChangeStorage: () => void;
  onImport: () => void;
}

export function StatusView({ onPair, onChangeStorage, onImport }: Props) {
  const [status, setStatus] = useState<Status | null>(null);
  const [retrying, setRetrying] = useState<string | null>(null);
  const [certificateNote, setCertificateNote] = useState<string | null>(null);
  // "Keep for now" on the banner about the other storage's pairings (certificate-password-pairing-plan.md §5.3).
  const [keepMixed, setKeepMixed] = useState(false);

  const refresh = useCallback(() => {
    void window.agent.getStatus().then(setStatus);
  }, []);
  const unpairing = useUnpair(refresh);

  useEffect(() => {
    refresh();
    return window.agent.onStatusChanged(refresh);
  }, [refresh]);

  if (!status) return <main className="page" aria-busy="true" />;
  // First launch: choose where the signing key lives before anything else (§1.1).
  if (status.keyStorage.selected === null) {
    return <KeyStorageView status={status} onImport={onImport} onDone={refresh} />;
  }

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
  const storage = status.keyStorage;
  const selected: KeySourceView = storage.selected ?? 'platform';
  const other: KeySourceView = selected === 'platform' ? 'pkcs12' : 'platform';
  const certificate = storage.certificate;
  // One key storage at a time (certificate-password-pairing-plan.md §5): every
  // pairing is listed. Pairings of the other storage only survive from an
  // older version (§5.3), and the banner below offers to unpair them.
  const shown = status.servers;
  const mixed = status.servers.filter((s) => s.keySource !== selected);
  const canPair = selected === 'platform' || certificate !== null;

  const unpairMixed = () => void window.agent.switchKeyStorage(selected).then(refresh);
  const removeCertificate = async (c: CertificateView) => {
    setCertificateNote(null);
    const result = await window.agent.removeCertificate(c.id);
    if (!result.ok) setCertificateNote(result.error);
    refresh();
  };

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
            <span className="storage-row">
              {selected === 'pkcs12' ? (
                <span className="badge badge-strong">
                  {certificate ? `Certificate · ${certificate.commonName}` : keyStorageLabel(status.platform, 'pkcs12')}
                </span>
              ) : caps.hardware ? (
                <span className="badge badge-strong">{keyStorageLabel(status.platform, 'platform')}</span>
              ) : (
                <span className="badge badge-weak">Software · lower assurance</span>
              )}
              <button type="button" className="link-button" onClick={onChangeStorage}>
                Change
              </button>
            </span>
            {selected === 'pkcs12' && certificate && (
              <span className="muted small storage-detail">
                {certificate.issuerName} · until {formatDate(certificate.notAfter)}
              </span>
            )}
            {selected === 'pkcs12' && certificate?.expiresSoon && (
              <span className="warning small storage-detail">Expires soon: renew it and import the new file.</span>
            )}
          </dd>
          {(selected === 'platform' || certificate) && (
            <>
              <dt>Approval</dt>
              <dd>
                {selected === 'pkcs12' && certificate
                  ? certificateApproval(status.platform, certificate)
                  : caps.userPresence
                    ? presenceLabel(status.platform, true)
                    : 'Not available'}
              </dd>
            </>
          )}
          {selected === 'platform' && (
            <>
              <dt>Attestation</dt>
              <dd>{caps.attestation ? 'Yes' : 'No'}</dd>
            </>
          )}
        </dl>
        {selected === 'pkcs12' && !certificate && (
          <div className="warning small">
            <p>No certificate imported yet. Import your .p12 or .pfx to pair apps with it.</p>
            <IconButton icon="download" label="Import certificate" variant="primary" tip="above" onClick={onImport} />
          </div>
        )}
        {selected === 'pkcs12' && certificate && (
          <details className="other-devices small">
            <summary className="muted">Certificate details</summary>
            <dl className="facts certificate-facts">
              <dt>Subject</dt>
              <dd>{certificate.subject}</dd>
              <dt>Issuer</dt>
              <dd>{certificate.issuer}</dd>
              <dt>Serial</dt>
              <dd className="mono">{certificate.serialHex}</dd>
              <dt>SHA-256</dt>
              <dd className="mono">{certificate.fingerprint256}</dd>
              <dt>Valid</dt>
              <dd>
                {formatDate(certificate.notBefore)} – {formatDate(certificate.notAfter)}
              </dd>
              <dt>Key held by</dt>
              <dd>{certificateHolder(status.platform, certificate)}</dd>
            </dl>
            <div className="button-row">
              <IconButton icon="download" label="Import a different certificate" tipAlign="start" onClick={onImport} />
              <IconButton
                icon="trash"
                label={certificate.usedBy.length > 0 ? 'Unpair its apps to remove it' : 'Remove certificate'}
                tipAlign="start"
                onClick={() => void removeCertificate(certificate)}
              />
            </div>
          </details>
        )}
        {certificateNote && (
          <p className="error small" role="alert">
            {certificateNote}
          </p>
        )}
      </section>

      <section className="card">
        <div className="card-title-row">
          <h2>Paired apps · {selected === 'pkcs12' ? 'certificate' : keyStorageLabel(status.platform, 'platform')}</h2>
          <IconButton
            icon="plus"
            label={canPair ? 'Pair with an app' : 'Import your certificate first'}
            variant="primary"
            disabled={!canPair}
            onClick={onPair}
          />
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
        {shown.length === 0 ? (
          <p className="muted">
            None yet. Open the website (<span className="mono">signature.uplb.edu.ph</span> for UPLB) and choose{' '}
            <strong>Pair this computer</strong>.
          </p>
        ) : (
          <ul className="server-list">
            {shown.map((s) => (
              <li key={s.id} className="server">
                <div>
                  <div className="server-name">
                    {s.name}
                    {s.insecure && <span className="badge badge-weak badge-inline">HTTP</span>}
                  </div>
                  <div className="mono muted">{s.origin}</div>
                  <div className="muted small">
                    {[s.userName, s.deviceLabel, deviceTypeLabel(s.deviceType), pairingKeyLabel(s)]
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
        {mixed.length > 0 && !keepMixed && (
          <div className="warning small" role="alert">
            <p>
              {mixed.map((s) => s.name).join(', ')} {mixed.length === 1 ? 'is' : 'are'} paired with{' '}
              {other === 'pkcs12' ? 'your certificate' : `the ${keyStorageLabel(status.platform, 'platform')}`}, not the key
              storage you chose. Unpair {mixed.length === 1 ? 'it' : 'them'} so this computer holds one kind of key, then pair
              again.
            </p>
            <div className="button-row">
              <IconButton icon="unlink" label="Unpair them" variant="primary" tipAlign="start" onClick={unpairMixed} />
              <IconButton icon="x" label="Keep for now" tipAlign="start" onClick={() => setKeepMixed(true)} />
            </div>
          </div>
        )}
        {selected === 'pkcs12' &&
          storage.olderCertificates
            .filter((c) => c.usedBy.length > 0)
            .map((c) => (
              <p key={c.id} className="warning small">
                {c.usedBy.join(', ')} still {c.usedBy.length === 1 ? 'signs' : 'sign'} with your older certificate (
                {c.commonName}, until {formatDate(c.notAfter)}). Pair {c.usedBy.length === 1 ? 'it' : 'them'} again to use{' '}
                {certificate?.commonName ?? 'the new one'}.
              </p>
            ))}
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

// The certificate's own password approves each use (certificate-password-pairing-plan.md §4).
function certificateApproval(_platform: Status['platform'], _c: CertificateView): string {
  return 'Certificate password';
}

function certificateHolder(platform: Status['platform'], _c: CertificateView): string {
  if (platform === 'macos') return 'Encrypted with its password, sealed to this Mac';
  if (platform === 'windows') return 'Encrypted with its password, protected by Windows';
  return 'Encrypted with its password';
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
