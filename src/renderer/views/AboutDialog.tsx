import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

import type { StatusView, UpdateView } from '../../shared/ipc';
import { Icon, IconButton } from '../icons';

interface Props {
  version: string;
  platform: StatusView['platform'];
  capabilities: StatusView['capabilities'];
  update: UpdateView;
  onClose: () => void;
}

// Opened from the version line: what the agent does on this computer, and
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
      <section ref={dialog} className="dialog" role="dialog" aria-modal="true" aria-labelledby="about-title" data-fit-overlay>
        <header className="dialog-header">
          <h2 id="about-title">Kukux Sign Agent</h2>
          <IconButton icon="x" label="Close" size="small" onClick={onClose} />
        </header>

        <UpdateLine version={version} update={update} />

        <div>
          <h3 className="dialog-section">What it does</h3>
          <ul className="feature-list">
            {features(platform, capabilities).map((line) => (
              <li key={line}>
                <Icon name="check" size={15} />
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>

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

function features(platform: StatusView['platform'], caps: StatusView['capabilities']): string[] {
  const mac = platform === 'macos';
  const chip = mac ? "this Mac's Secure Enclave" : "this PC's TPM";
  return [
    caps.hardware
      ? `Keeps your signing key in ${chip}, so it can't be copied off.`
      : 'Keeps your signing key on this computer (no security chip found).',
    caps.userPresence
      ? `Asks for ${mac ? 'Touch ID or your password' : 'Windows Hello'} every time you sign.`
      : 'Asks you to approve every signing.',
    'Shows the document and who’s signing before you approve.',
    'Works with several apps: one signature per app on this computer.',
    'Lets each app show which computer you signed on.',
    'Updates itself.',
  ];
}

function UpdateLine({ version, update }: { version: string; update: UpdateView }) {
  const install = () => void window.agent.installUpdate();
  switch (update.state) {
    case 'available':
      return (
        <div className="update-line">
          <span>
            Version {version} · <strong>{update.release.version}</strong> is out
          </span>
          <button type="button" className="button button-primary button-small" onClick={install}>
            {update.install === 'download' ? 'Update' : 'Download page'}
          </button>
        </div>
      );
    case 'downloading':
      return (
        <p className="update-line muted">
          Version {version} · Downloading {update.release.version}… {update.percent}%
        </p>
      );
    case 'ready':
      return (
        <div className="update-line">
          <span>
            Version {version} · <strong>{update.release.version}</strong> is ready
          </span>
          <button type="button" className="button button-primary button-small" onClick={install}>
            Restart to update
          </button>
        </div>
      );
    case 'checking':
      return <p className="update-line muted">Version {version} · Checking for updates…</p>;
    case 'up_to_date':
      return <p className="update-line muted">Version {version} · Up to date</p>;
    case 'error':
      return (
        <p className="update-line muted" title={update.message}>
          Version {version} · Couldn’t check for updates
        </p>
      );
    default:
      return <p className="update-line muted">Version {version}</p>;
  }
}
