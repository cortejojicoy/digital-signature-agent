// Import a .p12 / .pfx (pkcs12-key-storage-plan.md §7.2):
// choose file → password → preview → import.
//
// The page never sees the file's path or bytes, only a token from the main
// process. The password goes to the main process once per attempt and is
// never stored.
import { useState, type FormEvent } from 'react';

import type { CertificatePreviewView, CertificateView } from '../../shared/ipc';
import { Icon } from '../icons';
import { formatDate } from '../labels';
import { Button, Notice, PageHeader, PasswordField, ResultView } from '../ui';

interface Props {
  onDone: () => void;
  onBack: () => void;
}

export function ImportCertificateView({ onDone, onBack }: Props) {
  const [file, setFile] = useState<{ token: string; fileName: string } | null>(null);
  const [password, setPassword] = useState('');
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
    if (preview) {
      void doImport();
      return;
    }
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
      <ResultView
        title={`Imported ${imported.commonName}`}
        sub="Key locked to this computer. Keep the file offline as a backup."
        onDone={onDone}
      />
    );
  }

  return (
    <form className="page" onSubmit={(e) => void open(e)}>
      <PageHeader title="Import certificate" sub="A .p12 or .pfx file, such as PNPKI." onBack={busy === 'importing' ? undefined : onBack} />

      <section className="card">
        <div className="inset-row">
          <span className="tile tile-xs tile-file">
            <Icon name="file" />
          </span>
          <span className={`grow ${file ? 'mono' : 'sub'}`}>{file ? file.fileName : 'No file chosen'}</span>
          <Button size="sm" disabled={busy !== null} onClick={() => void choose()} autoFocus={!file}>
            {file ? 'Change' : 'Choose file…'}
          </Button>
        </div>

        {file && (
          <PasswordField
            label="Password"
            value={password}
            onChange={(v) => {
              setPassword(v);
              setPreview(null);
            }}
            disabled={busy !== null}
            autoFocus
          />
        )}

        {error && (
          <Notice tone="error" role="alert">
            {error}
          </Notice>
        )}

        {preview && <Preview preview={preview} />}
      </section>

      <div className="actions">
        <Button size="lg" disabled={busy === 'importing'} onClick={onBack}>
          Cancel
        </Button>
        {preview ? (
          <Button type="submit" size="lg" variant="primary" icon="download" disabled={busy !== null}>
            {busy === 'importing' ? 'Importing…' : preview.alreadyImported ? 'Use this certificate' : 'Import'}
          </Button>
        ) : (
          <Button type="submit" size="lg" variant="primary" icon="lock" disabled={!file || busy !== null}>
            {busy === 'opening' ? 'Opening…' : 'Open'}
          </Button>
        )}
      </div>
    </form>
  );
}

function Preview({ preview }: { preview: CertificatePreviewView }) {
  return (
    <div className="divider-top preview" aria-live="polite">
      <div className="row">
        <span className="tile tile-sm">
          <Icon name="certificate" size={20} />
        </span>
        <div className="grow">
          <div className="title-row">
            <span className="title">{preview.commonName}</span>
            {preview.pnpki && <span className="badge">PNPKI</span>}
          </div>
          {preview.organization && <div className="sub">{preview.organization}</div>}
        </div>
      </div>
      <dl className="facts facts-small selectable">
        <dt>Issued by</dt>
        <dd>{preview.issuerName}</dd>
        <dt>Valid until</dt>
        <dd>{formatDate(preview.notAfter)}</dd>
        <dt>Key</dt>
        <dd>{preview.algorithm}</dd>
        <dt>Serial</dt>
        <dd className="mono">{preview.serialHex}</dd>
      </dl>
      {preview.chain.length > 1 && (
        <details>
          <summary>Issuer chain · {preview.chain.length}</summary>
          <ol className="chain-list">
            {preview.chain.map((name, i) => (
              <li key={i}>{name}</li>
            ))}
          </ol>
        </details>
      )}
      {preview.warnings.map((warning) => (
        <Notice key={warning} tone="warning">
          {warning}
        </Notice>
      ))}
      {preview.alreadyImported && <Notice tone="info">Already on this computer.</Notice>}
    </div>
  );
}
