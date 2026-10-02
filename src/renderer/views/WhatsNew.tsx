import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

import type { UpdateView, WhatsNewEntry, WhatsNewView } from '../../shared/ipc';
import { Icon, IconButton } from '../icons';

// "What's new": opened from the version line. Short notes per version, from
// CHANGELOG.md (bundled) and, for an available update, its GitHub release.
export function WhatsNewDialog({ update, onClose }: { update: UpdateView; onClose: () => void }) {
  const [view, setView] = useState<WhatsNewView | null>(null);
  const dialog = useRef<HTMLElement>(null);

  // Refresh when the update state changes, so a new version shows up.
  useEffect(() => {
    void window.agent.getWhatsNew().then(setView);
  }, [update.state]);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    dialog.current?.querySelector<HTMLElement>('button')?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      opener?.focus();
    };
  }, [onClose]);

  // On <body>, outside the version line's aria-live region.
  return createPortal(
    <div className="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <section ref={dialog} className="dialog" role="dialog" aria-modal="true" aria-labelledby="whats-new-title" data-fit-overlay>
        <header className="dialog-header">
          <h2 id="whats-new-title">What's new</h2>
          <IconButton icon="x" label="Close" size="small" onClick={onClose} />
        </header>

        {view && <UpdateLine current={view.current} update={update} />}

        {view === null ? (
          <p className="muted small">Loading…</p>
        ) : view.entries.length === 0 ? (
          <p className="muted small">No notes yet.</p>
        ) : (
          <ol className="release-list">
            {view.entries.map((entry) => (
              <Release key={entry.version} entry={entry} />
            ))}
          </ol>
        )}

        <footer className="dialog-footer">
          <button type="button" className="link-button" onClick={() => void window.agent.openReleases()}>
            All releases <Icon name="external" size={13} />
          </button>
        </footer>
      </section>
    </div>,
    document.body,
  );
}

function UpdateLine({ current, update }: { current: string; update: UpdateView }) {
  const install = () => void window.agent.installUpdate();
  switch (update.state) {
    case 'available':
      return (
        <div className="update-line">
          <span>
            <strong>{update.release.version}</strong> is out.
          </span>
          <button type="button" className="button button-primary button-small" onClick={install}>
            {update.install === 'download' ? 'Get it' : 'Download page'}
          </button>
        </div>
      );
    case 'downloading':
      return <p className="update-line muted">Downloading {update.release.version}… {update.percent}%</p>;
    case 'ready':
      return (
        <div className="update-line">
          <span>
            <strong>{update.release.version}</strong> is ready.
          </span>
          <button type="button" className="button button-primary button-small" onClick={install}>
            Restart to update
          </button>
        </div>
      );
    case 'checking':
      return <p className="update-line muted">You're on {current}. Checking for updates…</p>;
    case 'up_to_date':
      return <p className="update-line muted">You're on {current}. All caught up.</p>;
    case 'error':
      return <p className="update-line muted">You're on {current}. Couldn't check for updates just now.</p>;
    default:
      return <p className="update-line muted">You're on {current}.</p>;
  }
}

const TAGS: Record<NonNullable<WhatsNewEntry['tag']>, { label: string; className: string }> = {
  new: { label: 'New', className: 'badge badge-strong' },
  current: { label: 'You have this', className: 'badge badge-quiet' },
  unreleased: { label: 'In progress', className: 'badge badge-weak' },
};

function Release({ entry }: { entry: WhatsNewEntry }) {
  const tag = entry.tag ? TAGS[entry.tag] : null;
  return (
    <li className="release">
      <div className="release-head">
        <strong>{entry.version === 'Unreleased' ? 'Next up' : entry.version}</strong>
        {tag && <span className={tag.className}>{tag.label}</span>}
        {entry.date && <span className="muted small release-date">{formatDate(entry.date)}</span>}
      </div>
      {entry.highlights.length > 0 ? (
        <ul className="release-notes">
          {entry.highlights.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      ) : (
        <p className="muted small">No notes for this one. See all releases below.</p>
      )}
    </li>
  );
}

/** "2026-10-01" → "Oct 1, 2026", read as a calendar date (no time zone shift). */
function formatDate(date: string): string {
  const [y, m, d] = date.split('-').map(Number);
  const value = new Date(y, (m ?? 1) - 1, d ?? 1);
  return Number.isNaN(value.getTime()) ? date : value.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}
