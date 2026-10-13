import type { DeviceType, KeySourceView, ProtectionLevel, StatusView } from '../shared/ipc';

export function protectionLabel(p: ProtectionLevel): string {
  switch (p) {
    case 'secure_enclave':
      return 'Secure Enclave';
    case 'tpm':
      return 'TPM';
    default:
      return 'Software';
  }
}

/** The chip's name on this platform, or "Certificate" (pkcs12-key-storage-plan.md §7.5). */
export function keyStorageLabel(platform: StatusView['platform'] | 'unknown', source: KeySourceView): string {
  if (source === 'pkcs12') return 'Software certificate';
  return platform === 'windows' ? 'TPM' : 'Secure Enclave';
}

/** "Certificate · Test UP 4" for certificate pairings, the protection otherwise. */
export function pairingKeyLabel(s: { keySource: KeySourceView; certificateName?: string; protection: ProtectionLevel }): string {
  if (s.keySource === 'pkcs12') return s.certificateName ? `Certificate · ${s.certificateName}` : 'Certificate';
  return protectionLabel(s.protection);
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function presenceLabel(platform: StatusView['platform'] | 'unknown', userPresence: boolean): string {
  if (!userPresence) return 'No OS prompt';
  return platform === 'windows' ? 'Windows Hello' : 'Touch ID or password';
}

export function currentPlatform(): 'macos' | 'windows' | 'unknown' {
  const ua = navigator.userAgent;
  if (ua.includes('Mac OS X')) return 'macos';
  if (ua.includes('Windows')) return 'windows';
  return 'unknown';
}

const DEVICE_TYPE_LABELS: Record<DeviceType, string> = {
  macbook: 'MacBook',
  macbook_air: 'MacBook Air',
  macbook_pro: 'MacBook Pro',
  imac: 'iMac',
  mac_mini: 'Mac mini',
  mac_studio: 'Mac Studio',
  mac_pro: 'Mac Pro',
  laptop: 'Computer laptop',
  convertible: '2-in-1 laptop',
  desktop: 'Computer desktop',
  all_in_one: 'All-in-one PC',
  mini_pc: 'Mini PC',
  server: 'Server',
  chromebook: 'Chromebook',
  tablet: 'Tablet',
  ipad: 'iPad',
  android_tablet: 'Android tablet',
  iphone: 'iPhone',
  android: 'Android phone',
  phone: 'Other phone',
  virtual_machine: 'Virtual machine',
  other: 'Other device',
};

export function deviceTypeLabel(type: DeviceType | null | undefined): string {
  return type ? DEVICE_TYPE_LABELS[type] : DEVICE_TYPE_LABELS.other;
}
