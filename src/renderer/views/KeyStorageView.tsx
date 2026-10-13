// "Where should your signing key live?" (pkcs12-key-storage-plan.md §1.1, §7.1).
// Shown on first launch, and from Change next to Key storage.
import { useState } from 'react';

import type { KeySourceView, StatusView } from '../../shared/ipc';
import { Icon, IconButton } from '../icons';
import { formatDate, keyStorageLabel } from '../labels';

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
  const chip = keyStorageLabel(status.platform, 'platform');
  const isMac = status.platform !== 'windows';

  const proceed = async () => {
    if (choice === 'pkcs12' && !storage.certificate) {
      onImport();
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

  return (
    <main className="page">
      <header className="page-header">
        <p className="eyebrow">Kukux Sign Agent</p>
        <h1>Where should your signing key live?</h1>
        <p className="muted">You can change this later. Each app you pair uses the storage chosen when you pair it.</p>
      </header>

      <div className="choices" role="radiogroup" aria-label="Key storage">
        <label className={`choice ${choice === 'platform' ? 'is-selected' : ''}`}>
          <input
            type="radio"
            name="storage"
            checked={choice === 'platform'}
            onChange={() => setChoice('platform')}
            autoFocus={choice === 'platform'}
          />
          <span className="choice-icon" aria-hidden="true">
            <Icon name="chip" size={22} />
          </span>
          <span className="choice-body">
            <span className="choice-title">
              {isMac ? `This Mac's ${chip}` : `This PC's ${chip} and Windows Hello`}
            </span>
            {storage.platform.available ? (
              <span className="muted small">
                A new key is made inside the chip and can't be copied. {isMac ? 'Touch ID or your password' : 'Windows Hello'}{' '}
                approves each use.
              </span>
            ) : (
              <span className="warning small">This computer has no security chip; keys would be software only.</span>
            )}
          </span>
        </label>

        <label className={`choice ${choice === 'pkcs12' ? 'is-selected' : ''} ${storage.certificatesSupported ? '' : 'is-disabled'}`}>
          <input
            type="radio"
            name="storage"
            checked={choice === 'pkcs12'}
            disabled={!storage.certificatesSupported}
            onChange={() => setChoice('pkcs12')}
            autoFocus={choice === 'pkcs12'}
          />
          <span className="choice-icon" aria-hidden="true">
            <Icon name="certificate" size={22} />
          </span>
          <span className="choice-body">
            <span className="choice-title">Software certificate (PKCS#12)</span>
            {storage.certificatesSupported ? (
              <span className="muted small">
                Import a .p12 or .pfx file, such as your PNPKI certificate. Your name and issuer travel with each signature.
              </span>
            ) : (
              <span className="warning small">Importing a certificate needs macOS 15 or later.</span>
            )}
            {storage.certificate && (
              <span className="small">
                Imported: <strong>{storage.certificate.commonName}</strong> · until {formatDate(storage.certificate.notAfter)}
              </span>
            )}
          </span>
        </label>
      </div>

      <div className="actions">
        {onCancel && <IconButton icon="back" label="Back" tip="above" onClick={onCancel} />}
        <IconButton
          icon="check"
          label={choice === 'pkcs12' && !storage.certificate ? 'Continue to import' : 'Continue'}
          variant="primary"
          tip="above"
          disabled={busy}
          onClick={() => void proceed()}
        />
      </div>
    </main>
  );
}
