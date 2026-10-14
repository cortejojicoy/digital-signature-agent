import { useEffect, useState } from 'react';

import type { AgentBridge, StatusView as Status } from '../shared/ipc';
import { CertificatePairView } from './views/CertificatePairView';
import { ConfirmView } from './views/ConfirmView';
import { ImportCertificateView } from './views/ImportCertificateView';
import { KeyStorageView } from './views/KeyStorageView';
import { PairView } from './views/PairView';
import { StatusView } from './views/StatusView';

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
  | { name: 'pair-certificate'; origin: string; code: string };

function parseHash(): Route {
  const hash = window.location.hash.replace(/^#/, '');
  const confirm = /^\/confirm\/([0-9a-f-]{36})$/.exec(hash);
  if (confirm) return { name: 'confirm', jobId: confirm[1] };
  if (hash === '/pair') return { name: 'pair' };
  return { name: 'status' };
}

export function App() {
  const [route, setRoute] = useState<Route>(parseHash);

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHash);
    const off = window.agent.onPairPrefill((p) =>
      setRoute(p.certificate ? { name: 'pair-certificate', origin: p.origin, code: p.code } : { name: 'pair', origin: p.origin, code: p.code }),
    );
    return () => {
      window.removeEventListener('hashchange', onHash);
      off();
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
        />
      );
  }
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
