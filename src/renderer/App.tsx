import { useEffect, useState } from 'react';

import type { AgentBridge } from '../shared/ipc';
import { ConfirmView } from './views/ConfirmView';
import { PairView } from './views/PairView';
import { StatusView } from './views/StatusView';

declare global {
  interface Window {
    agent: AgentBridge;
  }
}

type Route = { name: 'status' } | { name: 'pair'; origin?: string; code?: string } | { name: 'confirm'; jobId: string };

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
    const off = window.agent.onPairPrefill((p) => setRoute({ name: 'pair', origin: p.origin, code: p.code }));
    return () => {
      window.removeEventListener('hashchange', onHash);
      off();
    };
  }, []);

  switch (route.name) {
    case 'confirm':
      return <ConfirmView jobId={route.jobId} />;
    case 'pair':
      return (
        <PairView
          key={`${route.origin ?? ''}|${route.code ?? ''}`}
          initialOrigin={route.origin}
          initialCode={route.code}
          onDone={() => setRoute({ name: 'status' })}
        />
      );
    default:
      return <StatusView onPair={() => setRoute({ name: 'pair' })} />;
  }
}
