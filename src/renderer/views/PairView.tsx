import { useEffect, useState, type FormEvent, type ReactNode } from 'react';

import type { KeySourceView, PairingProgressView, PairingResult, ServerView } from '../../shared/ipc';
import { Icon } from '../icons';
import { currentPlatform } from '../labels';
import { Button, Notice, PageHeader, ResultView, Spinner } from '../ui';
import { OfflinePrompt, useUnpair } from '../unpair';

interface Props {
  initialOrigin?: string;
  initialCode?: string;
  onDone: () => void;
  /** Certificate mode: continue on the password screen (certificate-password-pairing-plan.md §3.4). */
  onCertificate: (origin: string, code: string) => void;
}

// A pasted kukuxsign://pair?o=…&c=… link fills both fields. The main process
// validates everything again; this is only a convenience.
function fromPastedLink(text: string): { origin: string; code: string } | null {
  try {
    const url = new URL(text.trim());
    if (url.protocol !== 'kukuxsign:' || url.host !== 'pair') return null;
    return { origin: url.searchParams.get('o') ?? '', code: url.searchParams.get('c') ?? '' };
  } catch {
    return null;
  }
}

// Loose match for the "already paired" notice only; the main process decides.
function sameOrigin(a: string, b: string): boolean {
  const norm = (v: string) => v.trim().toLowerCase().replace(/\/+$/, '');
  return norm(a) !== '' && norm(a) === norm(b);
}

type Failure = Extract<PairingResult, { ok: false }>;

export function PairView({ initialOrigin = '', initialCode = '', onDone, onCertificate }: Props) {
  const [origin, setOrigin] = useState(initialOrigin);
  const [code, setCode] = useState(initialCode);
  const [progress, setProgress] = useState<PairingProgressView | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [running, setRunning] = useState(false);
  const [paired, setPaired] = useState<{ serverName: string; rebound: boolean } | null>(null);
  const [servers, setServers] = useState<ServerView[]>([]);
  const [certificateMode, setCertificateMode] = useState(false);
  const unpairing = useUnpair();

  useEffect(() => window.agent.onPairingProgress(setProgress), []);
  useEffect(() => {
    const load = () =>
      void window.agent.getStatus().then((s) => {
        setServers(s.servers);
        setCertificateMode(s.keyStorage.selected === 'pkcs12');
      });
    load();
    return window.agent.onStatusChanged(load);
  }, []);

  // One signature per app on this computer: say so before the user submits.
  const holder = servers.find((s) => sameOrigin(s.origin, origin));

  const unpair = async (serverId: string) => {
    if (await unpairing.unpair(serverId)) setFailure(null);
  };
  const removeAnyway = async () => {
    if (await unpairing.removeAnyway()) setFailure(null);
  };

  const applyPaste = (value: string, set: (v: string) => void) => {
    const link = fromPastedLink(value);
    if (link) {
      setOrigin(link.origin);
      setCode(link.code);
    } else {
      set(value);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (certificateMode) {
      onCertificate(origin, code);
      return;
    }
    setFailure(null);
    setProgress(null);
    setRunning(true);
    const result = await window.agent.startPairing({ origin, code });
    setRunning(false);
    if (result.ok) setPaired({ serverName: result.serverName, rebound: result.rebound });
    else setFailure(result);
  };

  if (paired) {
    return (
      <ResultView
        title={`${paired.rebound ? 'Re-paired' : 'Paired'} with ${paired.serverName}`}
        sub={paired.rebound ? 'Existing device updated with new keys. Return to your browser.' : 'Return to your browser to finish.'}
        onDone={onDone}
      />
    );
  }

  return (
    <form className="page" onSubmit={(e) => void submit(e)}>
      <PageHeader
        title="Pair an app"
        sub={
          <>
            On the app's website, choose <strong>Pair this computer</strong>. Paste the link or enter the details.
          </>
        }
        onBack={running ? undefined : onDone}
      />

      <section className="card">
        <label className="field">
          <span className="field-label">App address</span>
          <span className="input-wrap">
            <Icon name="globe" size={16} />
            <input
              className="mono"
              type="text"
              inputMode="url"
              placeholder="https://sign.example.gov.ph"
              value={origin}
              disabled={running}
              onChange={(e) => applyPaste(e.target.value, setOrigin)}
              autoFocus={!initialOrigin}
              required
            />
          </span>
        </label>

        {initialOrigin && <Notice tone="warning">Opened from a link. Check that this is your app.</Notice>}
        {holder && !running && (
          <Notice
            tone="warning"
            actions={
              <Button
                size="sm"
                icon="unlink"
                disabled={!!unpairing.busy || !!unpairing.offline}
                onClick={() => void unpair(holder.id)}
              >
                {unpairing.busy ? 'Unpairing…' : `Unpair ${holder.name}`}
              </Button>
            }
          >
            {holder.name} is already paired{holder.userName ? ` for ${holder.userName}` : ''}. Unpair to use another account, or
            continue to re-pair.
          </Notice>
        )}
        {unpairing.offline && (
          <OfflinePrompt
            serverName={unpairing.offline.serverName}
            busy={!!unpairing.busy}
            onRemove={() => void removeAnyway()}
            onKeep={unpairing.keep}
          />
        )}
        {unpairing.note && <Notice tone="info">{unpairing.note}</Notice>}

        <label className="field">
          <span className="field-label">Pairing code</span>
          <input
            className="code-input"
            type="text"
            placeholder="K7QM-2XPD"
            maxLength={64}
            value={code}
            disabled={running}
            onChange={(e) => applyPaste(e.target.value, setCode)}
            autoFocus={!!initialOrigin}
            required
          />
        </label>

        {progress && running && progress.stage === 'already_paired_locally' ? (
          <Notice
            tone="warning"
            role="alertdialog"
            actions={
              <>
                <Button size="sm" icon="x" onClick={() => void window.agent.confirmRepair(false)}>
                  Keep current
                </Button>
                <Button size="sm" variant="primary" icon="refresh" onClick={() => void window.agent.confirmRepair(true)}>
                  Re-pair
                </Button>
              </>
            }
          >
            {progress.from === progress.to ? (
              <>
                {progress.serverName} is already paired here{progress.userName ? ` (${progress.userName})` : ''}. Re-pair with new
                keys?
              </>
            ) : (
              <>
                {progress.serverName} uses {storageWords(progress.from)}
                {progress.userName ? ` (${progress.userName})` : ''}. Re-pair with {storageWords(progress.to)}?
              </>
            )}
          </Notice>
        ) : (
          progress && running && <ProgressLine progress={progress} />
        )}

        {failure && (
          <Notice
            tone="error"
            role="alert"
            actions={
              <>
                {failure.code === 'app_already_paired' && failure.serverId && (
                  <Button
                    size="sm"
                    icon="unlink"
                    disabled={!!unpairing.busy || !!unpairing.offline}
                    onClick={() => void unpair(failure.serverId!)}
                  >
                    {unpairing.busy ? 'Unpairing…' : `Unpair ${failure.serverName ?? 'that app'}`}
                  </Button>
                )}
                {(failure.code === 'account_already_paired' || failure.code === 'certificate_in_use') && failure.manageUrl && (
                  <Button size="sm" icon="external" onClick={() => void window.agent.openDevicesPage()}>
                    Open signing devices
                  </Button>
                )}
              </>
            }
          >
            {failure.error}
          </Notice>
        )}
      </section>

      <div className="actions">
        <Button size="lg" icon="x" onClick={() => (running ? void window.agent.cancelPairing() : onDone())}>
          Cancel
        </Button>
        <Button type="submit" size="lg" variant="primary" icon="link" disabled={running}>
          {running ? 'Pairing…' : 'Pair'}
        </Button>
      </div>
    </form>
  );
}

function storageWords(source: KeySourceView): string {
  if (source === 'pkcs12') return 'your certificate';
  return currentPlatform() === 'windows' ? 'the TPM' : 'the Secure Enclave';
}

function ProgressLine({ progress }: { progress: PairingProgressView }) {
  let text: ReactNode = null;
  switch (progress.stage) {
    case 'looking_up':
      text = 'Checking code…';
      break;
    case 'creating_keys':
      text = (
        <>
          <strong>Creating keys</strong> · approve with {currentPlatform() === 'windows' ? 'Windows Hello' : 'Touch ID'}
        </>
      );
      break;
    case 'awaiting_confirmation':
      text = (
        <>
          Confirm <strong>“{progress.existingDevice?.label ?? progress.deviceLabel}”</strong> in the web app
        </>
      );
      break;
    default:
      return null;
  }
  return (
    <div className="progress" role="status">
      <Spinner small />
      <span>{text}</span>
    </div>
  );
}
