// Verify a PDF: choose, drop or open a file with the agent → verdict.
//
// The main process reads and checks the file; this page only shows what it
// found. Everything from the server (issuer, title, labels, names) is shown
// as plain text.
import { useEffect, useState } from 'react';

import type { VerifyReportView, VerifyResult } from '../../shared/ipc';
import { COPY, copyTitle, describeEmbedded, describeSlot, type LookupSlot, type Tone, type Verdict } from '../../shared/verdict';
import { Icon } from '../icons';
import { Button, Hint, Notice, PageHeader, Spinner } from '../ui';

/** A file that arrived from outside the page: opened with the agent, or dropped on the window. */
export type VerifyRequest =
  | { kind: 'opened'; id: string; fileName: string; result: VerifyResult | null }
  | { kind: 'dropped'; id: string; file: File };

type State =
  | { phase: 'idle'; error?: string }
  | { phase: 'checking'; fileName: string }
  | { phase: 'done'; report: VerifyReportView };

interface Props {
  request?: VerifyRequest;
  onBack: () => void;
}

export function VerifyView({ request, onBack }: Props) {
  const [state, setState] = useState<State>({ phase: 'idle' });
  const [choosing, setChoosing] = useState(false);

  // `request` changes identity only for a new file, or when an opened file's result arrives.
  useEffect(() => {
    if (!request) return;
    if (request.kind === 'opened') {
      setState(request.result ? stateFor(request.result) : { phase: 'checking', fileName: request.fileName });
      return;
    }
    let live = true;
    setState({ phase: 'checking', fileName: request.file.name });
    void window.agent.verifyDroppedFile(request.file).then((result) => live && setState(stateFor(result)));
    return () => {
      live = false;
    };
  }, [request]);

  const choose = async () => {
    setChoosing(true);
    try {
      const result = await window.agent.chooseAndVerifyPdf();
      if (result) setState(stateFor(result));
    } finally {
      setChoosing(false);
    }
  };

  if (state.phase === 'done') {
    return <Report report={state.report} onAnother={() => setState({ phase: 'idle' })} onBack={onBack} />;
  }

  return (
    <main className="page">
      <PageHeader title="Verify a PDF" sub="Check a signed file against the app that issued it." onBack={onBack} />

      <section className="card drop-zone" aria-busy={state.phase === 'checking'}>
        {state.phase === 'checking' ? (
          <>
            <Spinner />
            <div className="title">Checking…</div>
            <div className="mono sub">{state.fileName}</div>
          </>
        ) : (
          <>
            <div className="empty-icon">
              <Icon name="document" />
            </div>
            <div className="title">Drop a PDF here</div>
            <div className="sub">or</div>
            <Button variant="primary" icon="file" disabled={choosing} onClick={() => void choose()} autoFocus>
              {choosing ? 'Checking…' : 'Choose a PDF…'}
            </Button>
          </>
        )}
      </section>

      {state.phase === 'idle' && state.error && (
        <Notice tone="error" role="alert">
          {state.error}
        </Notice>
      )}

      <Hint>The file stays on this computer. Only its fingerprint goes to your paired apps.</Hint>
    </main>
  );
}

function stateFor(result: VerifyResult): State {
  return result.ok ? { phase: 'done', report: result } : { phase: 'idle', error: result.error };
}

// ── The verdict ──

const TONE_ICON = { ok: 'checkCircle', warn: 'warning', bad: 'xCircle', info: 'info' } as const;

function Report({ report, onAnother, onBack }: { report: VerifyReportView; onAnother: () => void; onBack: () => void }) {
  const [openError, setOpenError] = useState<string | null>(null);
  const { verdict, record, inspection } = report;
  const document = record?.document ?? null;
  const context = { issuer: report.issuer, document };
  const copy = COPY[verdict];
  // Nothing paired: "the server didn't answer" would be wrong, there was no one to ask.
  const unpaired = !report.paired && verdict === 'lookup_failed';
  const title = unpaired ? 'Record not checked' : copyTitle(verdict, context);
  const lede = unpaired ? 'No app is paired here, so this only shows what the file says about itself.' : copy.lede(context);

  const open = async () => {
    setOpenError(null);
    const result = await window.agent.openVerifiedPdf(report.token);
    if (!result.ok) setOpenError(result.error ?? "The file couldn't be opened.");
  };

  return (
    <main className="page">
      <PageHeader title="Verify a PDF" onBack={onBack} />

      <section className={`card verdict verdict-${copy.tone}`} role="status" aria-live="polite">
        <div className="row row-top">
          <span className={`tile tile-sm verdict-mark verdict-mark-${copy.tone}`} aria-hidden="true">
            <Icon name={TONE_ICON[copy.tone]} size={20} />
          </span>
          <div className="grow">
            <h2 className="verdict-title">{title}</h2>
            <p className="verdict-lede">{lede}</p>
          </div>
        </div>
      </section>

      {!report.paired && <Notice tone="info">Pair with UPLB Signature to check the record.</Notice>}

      <section className="card">
        <div className="row">
          <span className="tile tile-xs tile-file">
            <Icon name="file" />
          </span>
          <div className="grow">
            <div className="title selectable verify-file-name">{document?.title ?? report.fileName}</div>
            <div className="sub">
              {[document?.title ? report.fileName : null, formatSize(report.size), versionLine(verdict, document)].filter(Boolean).join(' · ')}
            </div>
          </div>
        </div>

        {record && record.slots.length > 0 && (
          <ul className="slot-list" aria-label="Signatures">
            {record.slots.map((slot, i) => (
              <SlotRow key={`${slot.slot}|${i}`} slot={slot} />
            ))}
          </ul>
        )}
      </section>

      <section className="card" aria-labelledby="this-file-title">
        <h2 id="this-file-title" className="card-label">
          This file
        </h2>
        <dl className="facts facts-small">
          {describeEmbedded(inspection, report.trustIssuer).map(([label, value]) => (
            <FactRow key={label} label={label} value={value} />
          ))}
        </dl>
        <details>
          <summary>Fingerprint</summary>
          <dl className="facts facts-small selectable">
            <dt>SHA-256</dt>
            <dd className="mono">{inspection.sha256}</dd>
            {inspection.signedRevisionSha256 && inspection.signedRevisionSha256 !== inspection.sha256 && (
              <>
                <dt>As signed</dt>
                <dd className="mono">{inspection.signedRevisionSha256}</dd>
              </>
            )}
          </dl>
        </details>
      </section>

      {openError && (
        <Notice tone="error" role="alert">
          {openError}
        </Notice>
      )}

      <div className="actions">
        <Button size="lg" icon="external" onClick={() => void open()}>
          Open in your PDF viewer
        </Button>
        <Button size="lg" variant="primary" icon="refresh" onClick={onAnother}>
          Check another file
        </Button>
      </div>
    </main>
  );
}

function FactRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  );
}

function SlotRow({ slot }: { slot: LookupSlot }) {
  const { text, chip } = describeSlot(slot);
  const signedAt = slot.state === 'signed' && slot.signed_at ? formatWhen(slot.signed_at) : '';
  return (
    <li className="slot-row">
      <span className={`slot-dot slot-dot-${slot.state}`} aria-hidden="true">
        <Icon name={slot.state === 'signed' ? 'check' : slot.state === 'declined' ? 'x' : 'clock'} size={14} stroke={2} />
      </span>
      <div className="grow">
        <div className="title-row">
          <span className="slot-label">{slot.label || 'Signatory'}</span>
          {chip && <span className={`badge ${badgeClass(chip.tone)}`}>{chip.text}</span>}
        </div>
        <div className="sub">{signedAt ? `${text} · ${signedAt}` : text}</div>
      </div>
    </li>
  );
}

function badgeClass(tone: Tone): string {
  if (tone === 'bad') return 'badge-bad';
  if (tone === 'warn') return 'badge-warn';
  if (tone === 'info') return 'badge-info';
  return '';
}

/** "Version 1 of 2" when the record recognised this copy. */
function versionLine(verdict: Verdict, document: { version: number; versions: number } | null): string | null {
  if (!document || verdict === 'not_issued' || verdict === 'lookup_failed') return null;
  return document.versions > 1 ? `Version ${document.version} of ${document.versions}` : null;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}
