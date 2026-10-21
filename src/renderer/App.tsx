import { useEffect, useRef, useState } from 'react';

import type { AgentBridge, StatusView as Status } from '../shared/ipc';
import { CertificatePairView } from './views/CertificatePairView';
import { ConfirmView } from './views/ConfirmView';
import { ImportCertificateView } from './views/ImportCertificateView';
import { KeyStorageView } from './views/KeyStorageView';
import { PairView } from './views/PairView';
import { StatusView } from './views/StatusView';
import { VerifyView, type VerifyRequest } from './views/VerifyView';

declare global {
  interface Window {
    agent: AgentBridge;
  }
}

type Route =
  | { name: 'status' }
  | { name: 'pair'; origin?: string; code?: string }
  | { name: 'confirm'; jobId: string }
  // Key storage (pkcs12-key-storage-plan.md §7.1)
  | { name: 'storage' }
  | { name: 'import-certificate'; then?: { origin: string; code: string } | 'storage' }
  // "Open in Kukux Sign Agent" in certificate mode (certificate-password-pairing-plan.md §3)
  | { name: 'pair-certificate'; origin: string; code: string }
  // Verify a PDF: opened from the status screen, dropped on the window, or opened with the agent
  | { name: 'verify'; request?: VerifyRequest };

function parseHash(): Route {
  const hash = window.location.hash.replace(/^#/, '');
  const confirm = /^\/confirm\/([0-9a-f-]{36})$/.exec(hash);
  if (confirm) return { name: 'confirm', jobId: confirm[1] };
  if (hash === '/pair') return { name: 'pair' };
  return { name: 'status' };
}

let dropRequests = 0;

export function App() {
  const [route, setRoute] = useState<Route>(parseHash);
  const routeName = useRef(route.name);
  routeName.current = route.name;

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHash);
    const off = window.agent.onPairPrefill((p) =>
      setRoute(p.certificate ? { name: 'pair-certificate', origin: p.origin, code: p.code } : { name: 'pair', origin: p.origin, code: p.code }),
    );
    // Subscribed here, not in the view, so a quick result can't arrive before anyone listens.
    const offRequested = window.agent.onVerifyRequested((e) =>
      setRoute({ name: 'verify', request: { kind: 'opened', id: `os-${e.id}`, fileName: e.fileName, result: null } }),
    );
    const offFinished = window.agent.onVerifyFinished((e) =>
      setRoute((r) =>
        r.name === 'verify' && r.request?.kind === 'opened' && r.request.id === `os-${e.id}`
          ? { name: 'verify', request: { ...r.request, result: e.result } }
          : r,
      ),
    );
    // A PDF dropped on the status or verify screen is checked; elsewhere a drop does nothing.
    const onDragOver = (e: DragEvent) => {
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = canDrop(routeName.current) ? 'copy' : 'none';
    };
    const onDrop = (e: DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer?.files[0];
      if (!file || !canDrop(routeName.current)) return;
      setRoute({ name: 'verify', request: { kind: 'dropped', id: `drop-${++dropRequests}`, file } });
    };
    window.addEventListener('dragover', onDragOver);
    window.addEventListener('drop', onDrop);
    return () => {
      window.removeEventListener('hashchange', onHash);
      window.removeEventListener('dragover', onDragOver);
      window.removeEventListener('drop', onDrop);
      off();
      offRequested();
      offFinished();
    };
  }, []);

  switch (route.name) {
    case 'confirm':
      return <ConfirmView jobId={route.jobId} />;
    case 'storage':
      return (
        <StorageRoute
          onImport={() => setRoute({ name: 'import-certificate', then: 'storage' })}
          onDone={() => setRoute({ name: 'status' })}
        />
      );
    case 'import-certificate': {
      // Imported on the way to a pairing: continue with it.
      const then = route.then;
      const next = (): Route =>
        then === 'storage' ? { name: 'storage' } : then ? { name: 'pair-certificate', ...then } : { name: 'status' };
      return <ImportCertificateView onDone={() => setRoute(next())} onBack={() => setRoute({ name: 'status' })} />;
    }
    case 'pair-certificate':
      return (
        <CertificatePairView
          key={`${route.origin}|${route.code}`}
          origin={route.origin}
          code={route.code}
          onDone={() => setRoute({ name: 'status' })}
          onImport={() => setRoute({ name: 'import-certificate', then: { origin: route.origin, code: route.code } })}
        />
      );
    case 'verify':
      return <VerifyView request={route.request} onBack={() => setRoute({ name: 'status' })} />;
    case 'pair':
      return (
        <PairView
          key={`${route.origin ?? ''}|${route.code ?? ''}`}
          initialOrigin={route.origin}
          initialCode={route.code}
          onDone={() => setRoute({ name: 'status' })}
          onCertificate={(origin, code) => setRoute({ name: 'pair-certificate', origin, code })}
        />
      );
    default:
      return (
        <StatusView
          onPair={() => setRoute({ name: 'pair' })}
          onChangeStorage={() => setRoute({ name: 'storage' })}
          onImport={() => setRoute({ name: 'import-certificate' })}
          onVerify={() => setRoute({ name: 'verify' })}
        />
      );
  }
}

function canDrop(route: Route['name']): boolean {
  return route === 'status' || route === 'verify';
}

/** The chooser opened from Change: needs the current status to show what's there. */
function StorageRoute({ onImport, onDone }: { onImport: () => void; onDone: () => void }) {
  const [status, setStatus] = useState<Status | null>(null);
  useEffect(() => {
    void window.agent.getStatus().then(setStatus);
  }, []);
  if (!status) return <main className="page" aria-busy="true" />;
  return <KeyStorageView status={status} onImport={onImport} onDone={onDone} onCancel={onDone} />;
}
