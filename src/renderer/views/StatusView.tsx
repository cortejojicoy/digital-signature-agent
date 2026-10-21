import { useCallback, useEffect, useState, type ReactNode } from 'react';

import type { CertificateView, KeySourceView, ServerView, StatusView as Status, UpdateView } from '../../shared/ipc';
import { Icon } from '../icons';
import { deviceTypeLabel, formatDate, keyStorageLabel, presenceLabel } from '../labels';
import { Button, Hint, IconButton, Notice, displayOrigin, monogram } from '../ui';
import { OfflinePrompt, useUnpair } from '../unpair';
import { AboutDialog } from './AboutDialog';
import { KeyStorageView } from './KeyStorageView';

interface Props {
  onPair: () => void;
  /** Change next to the key storage (pkcs12-key-storage-plan.md §7.3). */
  onChangeStorage: () => void;
  onImport: () => void;
  onVerify: () => void;
}

export function StatusView({ onPair, onChangeStorage, onImport, onVerify }: Props) {
  const [status, setStatus] = useState<Status | null>(null);

  const refresh = useCallback(() => {
    void window.agent.getStatus().then(setStatus);
  }, []);

  useEffect(() => {
    refresh();
    return window.agent.onStatusChanged(refresh);
  }, [refresh]);

  if (!status) return <main className="page" aria-busy="true" />;
  // First launch: choose where the signing key lives before anything else (§1.1).
  if (status.keyStorage.selected === null) {
    return <KeyStorageView status={status} onImport={onImport} onDone={refresh} />;
  }

  return (
    <main className="page">
      <Header status={status} />
      <ComputerCard status={status} onChange={onChangeStorage} onImport={onImport} onChanged={refresh} />
      <AppsCard status={status} onPair={onPair} onChanged={refresh} />
      <VerifyCard onVerify={onVerify} />
      <DeveloperCard status={status} onChanged={refresh} />
    </main>
  );
}

// ── This computer ──

function ComputerCard({
  status,
  onChange,
  onImport,
  onChanged,
}: {
  status: Status;
  onChange: () => void;
  onImport: () => void;
  onChanged: () => void;
}) {
  const [note, setNote] = useState<string | null>(null);
  const caps = status.capabilities;
  const certificateMode = status.keyStorage.selected === 'pkcs12';
  const certificate = status.keyStorage.certificate;

  const remove = async (c: CertificateView) => {
    setNote(null);
    const result = await window.agent.removeCertificate(c.id);
    if (!result.ok) setNote(result.error);
    onChanged();
  };

  let tile: 'accent' | 'neutral' | 'warn' = 'accent';
  let title: ReactNode;
  let sub: string;
  if (certificateMode && certificate) {
    title = (
      <span className="title-row">
        <span className="title">{certificate.commonName}</span>
        {certificate.pnpki && <span className="badge">PNPKI</span>}
      </span>
    );
    sub = 'Password approves each use';
  } else if (certificateMode) {
    tile = 'neutral';
    title = <span className="title">Certificate file</span>;
    sub = 'No certificate imported yet';
  } else if (caps.hardware) {
    title = <span className="title">{keyStorageLabel(status.platform, 'platform')}</span>;
    sub = caps.userPresence ? `Approve with ${presenceLabel(status.platform, true)}` : 'No OS prompt on use';
  } else {
    tile = 'warn';
    title = (
      <span className="title-row">
        <span className="title">Software key</span>
        <span className="badge badge-warn">Lower assurance</span>
      </span>
    );
    sub = 'No security chip found';
  }

  return (
    <section className="card" aria-labelledby="computer-title">
      <h2 id="computer-title" className="card-label">
        This computer
      </h2>
      <div className="row">
        <div className={`tile ${tile === 'neutral' ? 'tile-neutral' : tile === 'warn' ? 'tile-warn' : ''}`}>
          <Icon name={certificateMode ? 'certificate' : 'chip'} size={22} />
        </div>
        <div className="grow">
          {title}
          <div className="sub">{sub}</div>
        </div>
        <Button icon="switch" onClick={onChange}>
          Change
        </Button>
      </div>

      {!certificateMode && caps.hardware && (
        <div className="chips">
          <Chip>Hardware key</Chip>
          {caps.attestation && <Chip>Attested</Chip>}
          <Chip>Can't be copied</Chip>
        </div>
      )}

      {certificateMode && !certificate && (
        <Notice
          tone="warning"
          actions={
            <Button size="sm" variant="primary" icon="download" onClick={onImport}>
              Import certificate
            </Button>
          }
        >
          Import your .p12 or .pfx to pair apps.
        </Notice>
      )}

      {certificate?.expiresSoon && certificateMode && (
        <Notice tone="warning" role="status">
          <strong>Expires {formatDate(certificate.notAfter)}.</strong> Import the renewed file.
        </Notice>
      )}

      {certificateMode && certificate && (
        <details>
          <summary>Certificate details</summary>
          <dl className="facts facts-small selectable">
            <dt>Issuer</dt>
            <dd>{certificate.issuerName}</dd>
            <dt>Valid</dt>
            <dd>
              {formatDate(certificate.notBefore)} – {formatDate(certificate.notAfter)}
            </dd>
            <dt>Serial</dt>
            <dd className="mono">{certificate.serialHex}</dd>
            <dt>SHA-256</dt>
            <dd className="mono">{certificate.fingerprint256}</dd>
            <dt>Key</dt>
            <dd>{certificateHolder(status.platform)}</dd>
          </dl>
          <div className="notice-actions details-actions">
            <Button size="sm" icon="download" onClick={onImport}>
              Import another
            </Button>
            <Button
              size="sm"
              icon="trash"
              disabled={certificate.usedBy.length > 0}
              title={certificate.usedBy.length > 0 ? 'Unpair its apps to remove it' : undefined}
              onClick={() => void remove(certificate)}
            >
              Remove
            </Button>
          </div>
        </details>
      )}

      {note && (
        <Notice tone="error" role="alert">
          {note}
        </Notice>
      )}
    </section>
  );
}

function Chip({ children }: { children: ReactNode }) {
  return (
    <span className="chip">
      <Icon name="check" size={14} stroke={2} />
      {children}
    </span>
  );
}

function certificateHolder(platform: Status['platform']): string {
  if (platform === 'macos') return 'Encrypted, sealed to this Mac';
  if (platform === 'windows') return 'Encrypted, protected by Windows';
  return 'Encrypted with its password';
}

// ── Paired apps: the only part that scrolls ──

function AppsCard({ status, onPair, onChanged }: { status: Status; onPair: () => void; onChanged: () => void }) {
  const [retrying, setRetrying] = useState<string | null>(null);
  // "Keep" on the notice about the other storage's pairings (certificate-password-pairing-plan.md §5.3).
  const [keepMixed, setKeepMixed] = useState(false);
  const unpairing = useUnpair(onChanged);

  const storage = status.keyStorage;
  const selected: KeySourceView = storage.selected ?? 'platform';
  const servers = status.servers;
  // One key storage at a time (§5): pairings of the other one only survive from an older version.
  const mixed = servers.filter((s) => s.keySource !== selected);
  const canPair = selected === 'platform' || storage.certificate !== null;
  const olderInUse = selected === 'pkcs12' ? storage.olderCertificates.filter((c) => c.usedBy.length > 0) : [];
  const empty = servers.length === 0 && status.pendingRevokes.length === 0;

  const retry = async (origin: string) => {
    setRetrying(origin);
    try {
      await window.agent.retryRevokes(origin);
    } finally {
      setRetrying(null);
      onChanged();
    }
  };

  return (
    <section className="card apps-card" aria-labelledby="apps-title">
      <div className="card-head">
        <h2 id="apps-title" className="card-label">
          Paired apps
        </h2>
        {servers.length > 0 && <span className="badge badge-count">{servers.length}</span>}
        <span className="grow" />
        <Button
          variant="primary"
          icon="plus"
          disabled={!canPair}
          title={canPair ? undefined : 'Import your certificate first'}
          onClick={onPair}
        >
          Pair app
        </Button>
      </div>
      {!empty && <Hint>One account per app · one computer per account</Hint>}

      <div className="apps-scroll">
        {unpairing.note && (
          <Notice tone="info" role="status">
            {unpairing.note}
          </Notice>
        )}
        {mixed.length > 0 && !keepMixed && (
          <Notice
            tone="warning"
            role="alert"
            actions={
              <>
                <Button
                  size="sm"
                  variant="primary"
                  icon="unlink"
                  onClick={() => void window.agent.switchKeyStorage(selected).then(onChanged)}
                >
                  Unpair {mixed.length === 1 ? 'it' : 'them'}
                </Button>
                <Button size="sm" onClick={() => setKeepMixed(true)}>
                  Keep for now
                </Button>
              </>
            }
          >
            {mixed.map((s) => s.name).join(', ')} {mixed.length === 1 ? 'uses' : 'use'} the other key storage. Unpair, then pair
            again.
          </Notice>
        )}
        {olderInUse.map((c) => (
          <Notice key={c.id} tone="warning">
            {c.usedBy.join(', ')} still {c.usedBy.length === 1 ? 'signs' : 'sign'} with {c.commonName} (until{' '}
            {formatDate(c.notAfter)}). Pair again to use the new certificate.
          </Notice>
        ))}

        {empty ? (
          <div className="empty">
            <div className="empty-icon">
              <Icon name="link" />
            </div>
            <div className="title">No apps yet</div>
            <div className="sub">
              On the app's website, choose <strong>Pair this computer</strong>.
            </div>
          </div>
        ) : (
          <ul className="app-list">
            {servers.map((s) => (
              <AppItem
                key={s.id}
                server={s}
                otherStorage={s.keySource !== selected}
                busy={unpairing.busy === s.id}
                offline={unpairing.offline?.serverId === s.id}
                onUnpair={() => void unpairing.unpair(s.id)}
                prompt={
                  unpairing.offline?.serverId === s.id && (
                    <OfflinePrompt
                      serverName={unpairing.offline.serverName}
                      busy={unpairing.busy === s.id}
                      onRemove={() => void unpairing.removeAnyway()}
                      onKeep={unpairing.keep}
                    />
                  )
                }
              />
            ))}
            {status.pendingRevokes.map((r) => (
              <li key={`${r.origin}|${r.queuedAt}`} className="app-item">
                <div className="tile tile-sm tile-warn">
                  <Icon name="clock" />
                </div>
                <div className="grow">
                  <div className="title-row">
                    <span className="title">{r.serverName}</span>
                    <span className="badge badge-warn">Unpairing</span>
                  </div>
                  <div className="mono sub">{displayOrigin(r.origin)}</div>
                  <div className="sub" title={`Removed here ${formatWhen(r.queuedAt)}. Until it hears, your account can't pair another computer.`}>
                    Server not notified yet · retrying hourly
                  </div>
                </div>
                <Button
                  size="sm"
                  icon="refresh"
                  spinning={retrying === r.origin}
                  disabled={retrying === r.origin}
                  onClick={() => void retry(r.origin)}
                >
                  Retry
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function AppItem({
  server: s,
  otherStorage,
  busy,
  offline,
  onUnpair,
  prompt,
}: {
  server: ServerView;
  otherStorage: boolean;
  busy: boolean;
  offline: boolean;
  onUnpair: () => void;
  prompt: ReactNode;
}) {
  const others = s.otherDevices.length;
  return (
    <li className="app-item">
      <div className="monogram">{monogram(s.name)}</div>
      <div className="grow">
        <div className="title-row">
          <span className="title">{s.name}</span>
          {s.insecure && <span className="badge badge-warn">HTTP</span>}
          {otherStorage && <span className="badge badge-warn">Other key</span>}
        </div>
        <div className="mono sub">{displayOrigin(s.origin)}</div>
        <div className="sub">{[s.userName, s.deviceLabel || deviceTypeLabel(s.deviceType)].filter(Boolean).join(' · ')}</div>
        {others > 0 && (
          <details>
            <summary>
              Also on {others} other {others === 1 ? 'device' : 'devices'}
            </summary>
            <ul>
              {s.otherDevices.map((d, i) => (
                <li key={i}>
                  {d.label}
                  {d.deviceType ? ` · ${deviceTypeLabel(d.deviceType)}` : ''}
                </li>
              ))}
            </ul>
          </details>
        )}
        {prompt}
      </div>
      <Button size="sm" icon="unlink" disabled={busy || offline} onClick={onUnpair}>
        {busy ? 'Unpairing…' : 'Unpair'}
      </Button>
    </li>
  );
}

// ── Verify a PDF ──

function VerifyCard({ onVerify }: { onVerify: () => void }) {
  return (
    <section className="card compact-card">
      <div className="row">
        <span className="tile tile-xs tile-neutral">
          <Icon name="document" />
        </span>
        <span className="grow">
          <span className="toggle-title">Verify a PDF</span>
          <span className="sub">Check a signed file against its record</span>
        </span>
        <Button size="sm" iconEnd="forward" onClick={onVerify}>
          Verify
        </Button>
      </div>
    </section>
  );
}

// ── Developer mode ──

function DeveloperCard({ status, onChanged }: { status: Status; onChanged: () => void }) {
  const dev = status.developerMode;
  return (
    <section className="card dev-card">
      <label className="toggle-row">
        <span className="tile tile-xs tile-neutral">
          <Icon name="code" />
        </span>
        <span className="grow">
          <span className="toggle-title">Developer mode</span>
          <span className="sub">{dev.locked ? 'Always on in npm run dev' : 'Allow local HTTP apps for testing'}</span>
        </span>
        <input
          type="checkbox"
          role="switch"
          className="switch"
          checked={dev.on}
          disabled={dev.locked}
          onChange={(e) => void window.agent.setDeveloperMode(e.target.checked).then(onChanged)}
        />
      </label>
    </section>
  );
}

// ── Header: name, version and the update control ──

function Header({ status }: { status: Status }) {
  const [update, setUpdate] = useState<UpdateView>({ state: 'idle' });
  const [showAbout, setShowAbout] = useState(false);
  const closeAbout = useCallback(() => setShowAbout(false), []);

  useEffect(() => {
    void window.agent.getUpdate().then(setUpdate);
    return window.agent.onUpdateChanged(setUpdate);
  }, []);

  const check = () => void window.agent.checkForUpdates();
  const install = () => void window.agent.installUpdate();

  let note: ReactNode = null;
  let control: ReactNode;
  switch (update.state) {
    case 'available':
      note = <span className="accent">{update.release.version} available</span>;
      control =
        update.install === 'download' ? (
          <Button variant="soft" icon="download" onClick={install}>
            Update
          </Button>
        ) : (
          <Button variant="soft" icon="external" onClick={install}>
            Download
          </Button>
        );
      break;
    case 'downloading':
      note = <span>Downloading {update.percent}%</span>;
      control = <IconButton icon="refresh" label="Downloading…" spinning disabled />;
      break;
    case 'ready':
      note = <span className="accent">{update.release.version} ready</span>;
      control = (
        <Button variant="soft" icon="refresh" onClick={install}>
          Restart
        </Button>
      );
      break;
    case 'checking':
      note = <span>Checking…</span>;
      control = <IconButton icon="refresh" label="Checking…" spinning disabled />;
      break;
    case 'up_to_date':
      note = (
        <span className="ok">
          <Icon name="checkCircle" size={14} stroke={2} />
          Up to date
        </span>
      );
      control = <IconButton icon="refresh" label={`Checked ${formatTime(update.checkedAt)} · check again`} onClick={check} />;
      break;
    case 'error':
      note = (
        <span className="error" title={update.message}>
          Update check failed
        </span>
      );
      control = <IconButton icon="refresh" label="Try again" onClick={check} />;
      break;
    default:
      control = <IconButton icon="refresh" label="Check for updates" onClick={check} />;
  }

  return (
    <header className="row">
      <div className="app-tile">
        <Icon name="shield" size={22} />
      </div>
      <div className="grow">
        <h1 className="app-title">Kukux Sign Agent</h1>
        <div className="version-line" aria-live="polite">
          <button type="button" className="link-btn" title="About this app" onClick={() => setShowAbout(true)}>
            v{status.version}
          </button>
          {note && <span aria-hidden="true">·</span>}
          {note}
        </div>
      </div>
      {control}
      {showAbout && (
        <AboutDialog
          version={status.version}
          platform={status.platform}
          capabilities={status.capabilities}
          update={update}
          onClose={closeAbout}
        />
      )}
    </header>
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
