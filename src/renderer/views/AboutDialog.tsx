import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

import type { StatusView, UpdateView } from '../../shared/ipc';
import { Icon } from '../icons';
import { Button, IconButton } from '../ui';

interface Props {
  version: string;
  platform: StatusView['platform'];
  capabilities: StatusView['capabilities'];
  update: UpdateView;
  onClose: () => void;
}

// Opened from the version: what the agent does on this computer, and
// whether it's up to date. Plain words, no changelog.
export function AboutDialog({ version, platform, capabilities, update, onClose }: Props) {
  const dialog = useRef<HTMLElement>(null);

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
      <section ref={dialog} className="dialog" role="dialog" aria-modal="true" aria-labelledby="about-title">
        <header className="row">
          <div className="app-tile">
            <Icon name="shield" size={22} />
          </div>
          <div className="grow dialog-header">
            <h2 id="about-title">Kukux Sign Agent</h2>
            <div className="sub">Version {version}</div>
          </div>
          <IconButton icon="x" label="Close" variant="ghost" onClick={onClose} />
        </header>

        <UpdateLine update={update} />

        <div>
          <h3 className="dialog-section">What it does</h3>
          <ul className="feature-list">
            {features(platform, capabilities).map((line) => (
              <li key={line}>
                <Icon name="check" size={16} stroke={2} />
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>

        <footer className="dialog-footer">
          <button type="button" className="link-btn link-accent" onClick={() => void window.agent.openReleases()}>
            All releases <Icon name="external" size={14} />
          </button>
        </footer>
      </section>
    </div>,
    document.body,
  );
}

function features(platform: StatusView['platform'], caps: StatusView['capabilities']): string[] {
  const mac = platform === 'macos';
  return [
    caps.hardware ? `Key stays in the ${mac ? 'Secure Enclave' : 'TPM'}` : 'Key stays on this computer',
    caps.userPresence ? `${mac ? 'Touch ID' : 'Windows Hello'} for every signature` : 'You approve every signature',
    'Shows document and signer first',
    'One signature per app',
    'Apps see which computer signed',
    'Updates itself',
  ];
}

function UpdateLine({ update }: { update: UpdateView }) {
  const install = () => void window.agent.installUpdate();
  switch (update.state) {
    case 'available':
      return (
        <div className="update-line update-line-accent">
          <Icon name="download" />
          <span className="grow">
            <strong>{update.release.version}</strong> is available
          </span>
          <Button size="sm" variant="primary" onClick={install}>
            {update.install === 'download' ? 'Update' : 'Download page'}
          </Button>
        </div>
      );
    case 'downloading':
      return (
        <div className="update-line">
          <Icon name="download" />
          <span className="grow">
            Downloading {update.release.version}… {update.percent}%
          </span>
        </div>
      );
    case 'ready':
      return (
        <div className="update-line update-line-accent">
          <Icon name="refresh" />
          <span className="grow">
            <strong>{update.release.version}</strong> is ready
          </span>
          <Button size="sm" variant="primary" onClick={install}>
            Restart
          </Button>
        </div>
      );
    case 'checking':
      return (
        <div className="update-line">
          <Icon name="refresh" />
          <span className="grow">Checking for updates…</span>
        </div>
      );
    case 'up_to_date':
      return (
        <div className="update-line">
          <Icon name="checkCircle" />
          <span className="grow">Up to date</span>
        </div>
      );
    case 'error':
      return (
        <div className="update-line" title={update.message}>
          <Icon name="warning" />
          <span className="grow">Couldn’t check for updates</span>
        </div>
      );
    default:
      return null;
  }
}
