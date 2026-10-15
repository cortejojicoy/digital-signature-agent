// Unpairing asks the server first. If it can't be reached, nothing changes
// until the user decides (one-computer-per-account-plan.md §7.1): remove the
// signature here anyway, with the revoke queued, or keep the pairing.
import { useState } from 'react';

import { Button, Notice } from './ui';

interface Offline {
  serverId: string;
  serverName: string;
}

export function useUnpair(onChanged?: () => void) {
  const [busy, setBusy] = useState<string | null>(null);
  const [offline, setOffline] = useState<Offline | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const run = async (serverId: string, mode: 'ask' | 'remove', serverName?: string): Promise<boolean> => {
    setBusy(serverId);
    setNote(null);
    try {
      const result = await window.agent.unpair(serverId, { offline: mode });
      if (result.status === 'unreachable') {
        setOffline({ serverId, serverName: result.serverName });
        return false;
      }
      setOffline(null);
      if (result.status === 'removed_locally') {
        setNote(`Removed here. ${serverName ?? 'The app'} will be told once it's reachable.`);
      }
      return true;
    } finally {
      setBusy(null);
      onChanged?.();
    }
  };

  return {
    busy,
    offline,
    note,
    /** Resolves true once the pairing is gone from this computer. */
    unpair: (serverId: string) => run(serverId, 'ask'),
    removeAnyway: () => (offline ? run(offline.serverId, 'remove', offline.serverName) : Promise.resolve(false)),
    keep: () => setOffline(null),
  };
}

export function OfflinePrompt({
  serverName,
  busy,
  onRemove,
  onKeep,
}: {
  serverName: string;
  busy: boolean;
  onRemove: () => void;
  onKeep: () => void;
}) {
  return (
    <Notice
      tone="warning"
      role="alertdialog"
      actions={
        <>
          <Button size="sm" icon="x" disabled={busy} onClick={onKeep}>
            Keep
          </Button>
          <Button size="sm" variant="primary" icon="unlink" disabled={busy} onClick={onRemove}>
            {busy ? 'Removing…' : 'Remove anyway'}
          </Button>
        </>
      }
    >
      <strong>Can't reach {serverName}.</strong> Remove it here anyway? It stays listed on {serverName} until it reconnects.
    </Notice>
  );
}
