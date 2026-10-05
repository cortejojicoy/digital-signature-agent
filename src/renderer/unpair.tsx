// Unpairing asks the server first. If it can't be reached, nothing changes
// until the user decides (one-computer-per-account-plan.md §7.1): remove the
// signature here anyway, with the revoke queued, or keep the pairing.
import { useState } from 'react';

import { IconButton } from './icons';

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
        setNote(`Removed from this computer. ${serverName ?? 'The app'} will be told when it's reachable.`);
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
    <div className="warning small" role="alertdialog" aria-label={`Can't reach ${serverName}`}>
      <p>
        <strong>Can't reach {serverName}.</strong> Remove your signature from this computer anyway? {serverName} will keep
        listing this computer until it reconnects. To pair a different computer before then, remove this one from{' '}
        <strong>My signing devices</strong> on the web.
      </p>
      <div className="actions">
        <IconButton icon="x" label="Keep the pairing" tip="above" disabled={busy} onClick={onKeep} />
        <IconButton
          icon="unlink"
          label={busy ? 'Removing…' : 'Remove anyway'}
          variant="primary"
          tip="above"
          disabled={busy}
          onClick={onRemove}
        />
      </div>
    </div>
  );
}
