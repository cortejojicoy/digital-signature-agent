// Import a .p12 / .pfx (pkcs12-key-storage-plan.md §7.2):
// choose file → password → preview → import.
//
// The page never sees the file's path or bytes, only a token from the main
// process. The password goes to the main process once per attempt and is
// never stored.
import { useState, type FormEvent } from 'react';

import type { CertificatePreviewView, CertificateView } from '../../shared/ipc';
import { Icon, IconButton } from '../icons';
import { formatDate } from '../labels';

interface Props {
  onDone: () => void;
  onBack: () => void;
}

export function ImportCertificateView({ onDone, onBack }: Props) {
  const [file, setFile] = useState<{ token: string; fileName: string } | null>(null);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [preview, setPreview] = useState<CertificatePreviewView | null>(null);
  const [imported, setImported] = useState<CertificateView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'choosing' | 'opening' | 'importing' | null>(null);

  const choose = async () => {
    setBusy('choosing');
    setError(null);
    try {
      const result = await window.agent.chooseCertificateFile();
      if (!result) return; // cancelled the file picker
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setFile({ token: result.token, fileName: result.fileName });
      setPreview(null);
      setPassword('');
    } finally {
      setBusy(null);
    }
  };

  const open = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy('opening');
    setError(null);
    try {
      const result = await window.agent.inspectCertificate({ token: file.token, password });
      if (result.ok) {
        setPreview(result.preview);
      } else {
        setError(result.error);
        if (result.code === 'file_expired') setFile(null);
      }
    } finally {
      setBusy(null);
    }
  };

  const doImport = async () => {
    if (!file) return;
    setBusy('importing');
    setError(null);
    try {
      const result = await window.agent.importCertificate({ token: file.token, password });
      if (result.ok) {
        setPassword('');
        setImported(result.certificate);
      } else {
        setError(result.error);
        if (result.code === 'file_expired') {
          setFile(null);
          setPreview(null);
        }
      }
    } finally {
      setBusy(null);
    }
  };

  if (imported) {
    return (
      <main className="page">
        <section className="card center">
          <div className="big-check" aria-hidden="true">✓</div>
          <h1>Imported {imported.commonName}</h1>
          <p className="muted">
            Its key is now locked to this computer and can't be exported. Keep your .p12 file somewhere safe and offline;
            this computer no longer needs it.
          </p>
          <IconButton icon="check" label="Done" variant="primary" tip="above" onClick={onDone} autoFocus />
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="page-header">
        <p className="eyebrow">Software certificate</p>
        <h1>Import your certificate</h1>
        <p className="muted">Choose your .p12 or .pfx file, such as your PNPKI certificate, and enter its password.</p>
      </header>

      <form className="card form" onSubmit={(e) => void open(e)}>
        <div className="file-row">
          <span className="choice-icon" aria-hidden="true">
            <Icon name="file" size={20} />
          </span>
          <span className={file ? 'mono' : 'muted'}>{file ? file.fileName : 'No file chosen'}</span>
          <button
            type="button"
            className="button button-quiet"
            disabled={busy !== null}
            onClick={() => void choose()}
            autoFocus={!file}
          >
            {file ? 'Change…' : 'Choose file…'}
          </button>
        </div>

        {file && (
          <label className="field">
            <span>Password</span>
            <div className="password-row">
              <input
                type={showPassword ? 'text' : 'password'}
                autoComplete="off"
                spellCheck={false}
                value={password}
                disabled={busy !== null}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setPreview(null);
                }}
                autoFocus
              />
              <IconButton
                icon={showPassword ? 'eyeOff' : 'eye'}
                label={showPassword ? 'Hide password' : 'Show password'}
                tip="above"
                onClick={() => setShowPassword((v) => !v)}
              />
            </div>
          </label>
        )}

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        {preview && <Preview preview={preview} />}

        <div className="actions">
          <IconButton icon="back" label="Back" tip="above" disabled={busy === 'importing'} onClick={onBack} />
          {preview ? (
            <IconButton
              icon="download"
              label={busy === 'importing' ? 'Importing…' : preview.alreadyImported ? 'Use this certificate' : 'Import'}
              variant="primary"
              tip="above"
              disabled={busy !== null}
              onClick={() => void doImport()}
            />
          ) : (
            <IconButton
              type="submit"
              icon="check"
              label={busy === 'opening' ? 'Opening…' : 'Open'}
              variant="primary"
              tip="above"
              disabled={!file || busy !== null}
            />
          )}
        </div>
      </form>
    </main>
  );
}

function Preview({ preview }: { preview: CertificatePreviewView }) {
  return (
    <div className="preview" aria-live="polite">
      <dl className="facts">
        <dt>Name</dt>
        <dd>
          <strong>{preview.commonName}</strong>
          {preview.pnpki && <span className="badge badge-strong badge-inline">PNPKI</span>}
        </dd>
        {preview.organization && (
          <>
            <dt>Organisation</dt>
            <dd>{preview.organization}</dd>
          </>
        )}
        <dt>Issued by</dt>
        <dd>{preview.issuerName}</dd>
        <dt>Valid until</dt>
        <dd>{formatDate(preview.notAfter)}</dd>
        <dt>Serial</dt>
        <dd className="mono">{preview.serialHex}</dd>
        <dt>Key</dt>
        <dd>{preview.algorithm}</dd>
      </dl>
      {preview.chain.length > 1 && (
        <details className="other-devices small">
          <summary className="muted">Issuer chain ({preview.chain.length} certificates)</summary>
          <ol className="chain-list">
            {preview.chain.map((name, i) => (
              <li key={i}>{name}</li>
            ))}
          </ol>
        </details>
      )}
      {preview.warnings.map((warning) => (
        <p key={warning} className="warning small">
          {warning}
        </p>
      ))}
      {preview.alreadyImported && <p className="muted small">This certificate is already on this computer.</p>}
    </div>
  );
}
