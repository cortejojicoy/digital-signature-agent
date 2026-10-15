// Shared building blocks: buttons with a label, notices, the password field
// and the centered result screen.
import { Children, Fragment, isValidElement, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';

import { Icon, type IconName } from './icons';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon?: IconName;
  /** An icon after the label, e.g. Continue →. */
  iconEnd?: IconName;
  variant?: 'primary' | 'secondary' | 'soft';
  /** sm: inside lists and notices; md: in cards; lg: a page's actions; block: fills its cell. */
  size?: 'sm' | 'md' | 'lg' | 'block';
  /** Spins the icon, e.g. while checking for updates. */
  spinning?: boolean;
}

export function Button({
  icon,
  iconEnd,
  variant = 'secondary',
  size = 'md',
  spinning = false,
  className = '',
  type = 'button',
  children,
  ...rest
}: ButtonProps) {
  const iconSize = size === 'sm' ? 15 : 16;
  return (
    <button type={type} className={`btn btn-${variant} btn-${size} ${spinning ? 'is-spinning' : ''} ${className}`.trim()} {...rest}>
      {icon && <Icon name={icon} size={iconSize} />}
      {children}
      {iconEnd && <Icon name={iconEnd} size={iconSize} />}
    </button>
  );
}

interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  icon: IconName;
  /** The accessible name, also shown as the native tooltip. */
  label: string;
  /** ghost: no border, e.g. inside a field or a dialog header. */
  variant?: 'secondary' | 'ghost';
  spinning?: boolean;
}

export function IconButton({ icon, label, variant = 'secondary', spinning = false, className = '', type = 'button', ...rest }: IconButtonProps) {
  return (
    <button
      type={type}
      className={`icon-btn icon-btn-${variant} ${spinning ? 'is-spinning' : ''} ${className}`.trim()}
      aria-label={label}
      title={label}
      {...rest}
    >
      <Icon name={icon} />
    </button>
  );
}

const NOTICE_ICONS = { warning: 'warning', error: 'xCircle', info: 'info' } as const;

/** A one-line message with its icon; `actions` go underneath. */
export function Notice({
  tone,
  children,
  actions,
  role,
}: {
  tone: keyof typeof NOTICE_ICONS;
  children: ReactNode;
  actions?: ReactNode;
  role?: 'alert' | 'status' | 'alertdialog';
}) {
  return (
    <div className={`notice notice-${tone}`} role={role}>
      <Icon name={NOTICE_ICONS[tone]} size={16} />
      <div className="notice-body">
        <p>{children}</p>
        {hasContent(actions) && <div className="notice-actions">{actions}</div>}
      </div>
    </div>
  );
}

// `<>{a && <X/>}{b && <Y/>}</>` with neither a nor b is still a fragment.
function hasContent(node: ReactNode): boolean {
  return Children.toArray(node).some((child) =>
    isValidElement<{ children?: ReactNode }>(child) && child.type === Fragment ? hasContent(child.props.children) : true,
  );
}

/** A small muted line with an info icon. */
export function Hint({ children }: { children: ReactNode }) {
  return (
    <p className="hint">
      <Icon name="info" size={14} />
      {children}
    </p>
  );
}

/** A screen's title, with Back when there is somewhere to go back to. */
export function PageHeader({ title, sub, onBack }: { title: string; sub?: ReactNode; onBack?: () => void }) {
  return (
    <header className="page-header">
      {onBack && <IconButton icon="back" label="Back" onClick={onBack} />}
      <div className="grow">
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
    </header>
  );
}

/** The app a request or pairing comes from: its initials, name and address. */
export function AppHeader({ eyebrow, name, detail }: { eyebrow: string; name: string; detail: ReactNode }) {
  return (
    <header className="request-header">
      <div className="monogram monogram-lg">{monogram(name)}</div>
      <div className="grow">
        <div className="eyebrow">{eyebrow}</div>
        <h1>{name}</h1>
        <div className="sub">{detail}</div>
      </div>
    </header>
  );
}

export function PasswordField({
  label,
  value,
  onChange,
  disabled,
  autoFocus,
  enterSubmits = true,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
  /** false: Enter does nothing (confirm windows approve on a click only). */
  enterSubmits?: boolean;
}) {
  const [show, setShow] = useState(false);
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <span className="input-wrap">
        <Icon name="lock" size={16} />
        <input
          type={show ? 'text' : 'password'}
          autoComplete="off"
          spellCheck={false}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={enterSubmits ? undefined : (e) => e.key === 'Enter' && e.preventDefault()}
          autoFocus={autoFocus}
        />
        <IconButton
          icon={show ? 'eyeOff' : 'eye'}
          label={show ? 'Hide password' : 'Show password'}
          variant="ghost"
          onClick={() => setShow((v) => !v)}
        />
      </span>
    </label>
  );
}

/** A finished step: big icon, one line, and Done. */
export function ResultView({
  tone = 'success',
  title,
  sub,
  children,
  onDone,
}: {
  tone?: 'success' | 'neutral' | 'error' | 'busy';
  title: string;
  sub?: ReactNode;
  children?: ReactNode;
  onDone?: () => void;
}) {
  return (
    <main className="page page-center" aria-live="polite">
      {tone === 'busy' ? (
        <div className="spinner" aria-hidden="true" />
      ) : (
        <div className={`result-icon result-${tone}`} aria-hidden="true">
          <Icon name={tone === 'success' ? 'check' : tone === 'error' ? 'xCircle' : 'x'} size={30} stroke={2} />
        </div>
      )}
      <div>
        <h1 className="result-title">{title}</h1>
        {sub && <p className="result-sub">{sub}</p>}
      </div>
      {children}
      {onDone && (
        <Button variant="primary" size="lg" onClick={onDone} autoFocus>
          Done
        </Button>
      )}
    </main>
  );
}

export function Spinner({ small = false }: { small?: boolean }) {
  return <span className={small ? 'spinner spinner-sm' : 'spinner'} aria-hidden="true" />;
}

/** "UPLB Signature" → "UP". */
export function monogram(name: string): string {
  const word = name.trim().split(/\s+/)[0] ?? '';
  return word.replace(/[^\p{L}\p{N}]/gu, '').slice(0, 2).toUpperCase() || '?';
}

/** The address without https://; plain http:// stays visible. */
export function displayOrigin(origin: string): string {
  return origin.replace(/^https:\/\//, '').replace(/\/+$/, '');
}
