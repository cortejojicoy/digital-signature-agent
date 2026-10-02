import type { DeviceType, ProtectionLevel, StatusView } from '../shared/ipc';

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
