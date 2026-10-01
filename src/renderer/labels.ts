import type { ProtectionLevel, StatusView } from '../shared/ipc';

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
