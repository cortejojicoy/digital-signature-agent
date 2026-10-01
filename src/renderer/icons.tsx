// Inline SVG icons (24×24, stroke-based) and an icon-only button whose label
// shows on hover and keyboard focus. The label is also its accessible name.
import type { ButtonHTMLAttributes, ReactNode } from 'react';

const PATHS = {
  plus: <path d="M12 5v14M5 12h14" />,
  check: <path d="M20 6 9 17l-5-5" />,
  x: <path d="M18 6 6 18M6 6l12 12" />,
  back: <path d="M19 12H5M12 19l-7-7 7-7" />,
  refresh: (
    <>
      <path d="M21 12a9 9 0 0 0-15.5-6.3L3 8" />
      <path d="M3 3v5h5" />
      <path d="M3 12a9 9 0 0 0 15.5 6.3L21 16" />
      <path d="M21 21v-5h-5" />
    </>
  ),
  download: (
    <>
      <path d="M12 3v12" />
      <path d="m7 10 5 5 5-5" />
      <path d="M5 21h14" />
    </>
  ),
  restart: (
    <>
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 3v5h5" />
    </>
  ),
  external: (
    <>
      <path d="M15 3h6v6" />
      <path d="M10 14 21 3" />
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    </>
  ),
  unlink: (
    <>
      <path d="m18.84 12.25 1.72-1.71a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="m5.17 11.75-1.71 1.71a5 5 0 0 0 7.07 7.07l1.71-1.71" />
      <path d="M8 2v3M2 8h3M16 22v-3M22 16h-3" />
    </>
  ),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  icon: IconName;
  label: string;
  variant?: 'primary' | 'quiet';
  /** Where the hover label appears: below by default, above for bottom-row buttons. */
  tip?: 'below' | 'above';
  /** Label edge aligned with the button: `end` for right-side buttons, `start` for left-side ones. */
  tipAlign?: 'end' | 'start';
  /** `small`: a borderless inline icon, e.g. next to text. */
  size?: 'normal' | 'small';
}

export function IconButton({
  icon,
  label,
  variant = 'quiet',
  tip = 'below',
  tipAlign = 'end',
  size = 'normal',
  className = '',
  type = 'button',
  ...rest
}: IconButtonProps) {
  return (
    <button
      type={type}
      className={`icon-button icon-button-${variant} ${size === 'small' ? 'icon-button-small' : ''} ${className}`
        .replace(/\s+/g, ' ')
        .trim()}
      aria-label={label}
      data-tip={label}
      data-tip-pos={tip}
      data-tip-align={tipAlign}
      {...rest}
    >
      <Icon name={icon} size={size === 'small' ? 15 : 18} />
    </button>
  );
}
