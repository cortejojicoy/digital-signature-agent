// "Where should your key live?" (pkcs12-key-storage-plan.md §1.1, §7.1).
// Shown on first launch, and from Change next to the key storage.
import { useState } from 'react';

import type { KeySourceView, StatusView, SwitchResultView } from '../../shared/ipc';
import { Icon } from '../icons';
import { formatDate, keyStorageLabel } from '../labels';
import { Button, Hint, Notice, PageHeader, ResultView, displayOrigin, monogram } from '../ui';

interface Props {
  status: StatusView;
  /** Software certificate chosen with none imported yet. */
  onImport: () => void;
  onDone: () => void;
  /** Absent on first launch: there is nothing to go back to. */
  onCancel?: () => void;
}

export function KeyStorageView({ status, onImport, onDone, onCancel }: Props) {
  const storage = status.keyStorage;
  const [choice, setChoice] = useState<KeySourceView>(storage.selected ?? (storage.platform.available ? 'platform' : 'pkcs12'));
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [removeCertificate, setRemoveCertificate] = useState(false);
  const [result, setResult] = useState<SwitchResultView | null>(null);
  const chip = keyStorageLabel(status.platform, 'platform');
  const isMac = status.platform !== 'windows';
  // One key storage at a time: switching unpairs the other one's apps
  // (certificate-password-pairing-plan.md §5).
  const leaving = status.servers.filter((s) => s.keySource !== choice);
  const target = choice === 'pkcs12' ? 'your certificate' : `the ${chip}`;

  const proceed = async () => {
    if (choice === 'pkcs12' && !storage.certificate) {
      onImport();
      return;
    }
    if (leaving.length > 0) {
      setConfirming(true);
      return;
    }
    setBusy(true);
    try {
      await window.agent.setKeyStorage(choice);
      onDone();
    } finally {
      setBusy(false);
    }
  };

  const switchNow = async () => {
    setBusy(true);
    try {
      const done = await window.agent.switchKeyStorage(choice, { removeCertificate });
      if (done.queued.length > 0 || done.failed.length > 0) setResult(done);
      else onDone();
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <ResultView title={`Switched to ${target}`} onDone={onDone}>
        {result.queued.length > 0 && (
          <Notice tone="info">
            {result.queued.join(', ')} couldn't be reached. Removed here; {result.queued.length === 1 ? "it'll" : "they'll"} be told
            once back.
          </Notice>
        )}
        {result.failed.length > 0 && <Notice tone="error">Couldn't remove: {result.failed.join(', ')}.</Notice>}
      </ResultView>
    );
  }

  if (confirming) {
    return (
      <main className="page">
        <PageHeader title={`Switch to ${target}?`} sub="These apps will be unpaired and their keys deleted." onBack={() => setConfirming(false)} />
        <section className="card">
          <ul className="leaving-list">
            {leaving.map((s) => (
              <li key={s.id} className="row">
                <div className="monogram">{monogram(s.name)}</div>
                <div className="grow">
                  <div className="title">{s.name}</div>
                  <div className="mono sub">{displayOrigin(s.origin)}</div>
                </div>
              </li>
            ))}
          </ul>
          <Hint>Pair them again afterwards.</Hint>
          {choice === 'platform' && storage.certificate && (
            <label className="check-row">
              <input type="checkbox" checked={removeCertificate} onChange={(e) => setRemoveCertificate(e.target.checked)} />
              Also remove {storage.certificate.commonName}'s certificate
            </label>
          )}
        </section>
        <div className="actions">
          <Button size="lg" disabled={busy} onClick={() => setConfirming(false)}>
            Cancel
          </Button>
          <Button size="lg" variant="primary" icon="unlink" disabled={busy} onClick={() => void switchNow()}>
            {busy ? 'Unpairing…' : 'Unpair & switch'}
          </Button>
        </div>
      </main>
    );
  }

  return (
    <main className="page">
      <PageHeader title="Where should your key live?" sub="You can change this later." onBack={onCancel} />

      <fieldset className="choices">
        <legend className="visually-hidden">Key storage</legend>
        <label className={`choice ${choice === 'platform' ? 'is-selected' : ''}`}>
          <span className={`tile ${choice === 'platform' ? '' : 'tile-neutral'}`}>
            <Icon name="chip" size={22} />
          </span>
          <span className="grow">
            <span className="title-row">
              <span className="title">{isMac ? 'Secure Enclave' : 'TPM + Windows Hello'}</span>
              {storage.platform.available && <span className="badge">Recommended</span>}
            </span>
            {storage.platform.available ? (
              <span className="sub">
                New key made in this {isMac ? "Mac's" : "PC's"} chip. Can't be copied. {isMac ? 'Touch ID' : 'Windows Hello'} approves
                each use.
              </span>
            ) : (
              <span className="choice-warning">No security chip here. The key would be software only.</span>
            )}
          </span>
          <input
            type="radio"
            name="storage"
            checked={choice === 'platform'}
            onChange={() => setChoice('platform')}
            autoFocus={choice === 'platform'}
          />
        </label>

        <label
          className={`choice ${choice === 'pkcs12' ? 'is-selected' : ''} ${storage.certificatesSupported ? '' : 'is-disabled'}`}
        >
          <span className={`tile ${choice === 'pkcs12' ? '' : 'tile-neutral'}`}>
            <Icon name="certificate" size={22} />
          </span>
          <span className="grow">
            <span className="title">Certificate file</span>
            {storage.certificatesSupported ? (
              <span className="sub">Import a .p12 or .pfx, like PNPKI. Its password approves each use.</span>
            ) : (
              <span className="choice-warning">Needs macOS 15 or later.</span>
            )}
            {storage.certificate && (
              <span className="sub">
                Imported: <strong>{storage.certificate.commonName}</strong> · until {formatDate(storage.certificate.notAfter)}
              </span>
            )}
          </span>
          <input
            type="radio"
            name="storage"
            checked={choice === 'pkcs12'}
            disabled={!storage.certificatesSupported}
            onChange={() => setChoice('pkcs12')}
            autoFocus={choice === 'pkcs12'}
          />
        </label>
      </fieldset>

      <div className="actions">
        <Button size="lg" variant="primary" iconEnd="forward" disabled={busy} onClick={() => void proceed()}>
          {choice === 'pkcs12' && !storage.certificate ? 'Continue to import' : 'Continue'}
        </Button>
      </div>
    </main>
  );
}
