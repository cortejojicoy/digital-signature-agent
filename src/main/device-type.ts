// Device-type catalogue and detection (multi-app-pairing-plan.md §4).
//
// Pure string logic over what the native module reports, so it's easy to
// test. The type is a label for people, never a security signal: assurance
// comes from the key's protection and attestation.
import type { DeviceInfo } from './keystore';

// Same order and values as test/fixtures/device-types.json and the package's
// DeviceType enum.
export const DEVICE_TYPES = [
  'macbook', 'macbook_air', 'macbook_pro', 'imac', 'mac_mini', 'mac_studio', 'mac_pro',
  'laptop', 'convertible', 'desktop', 'all_in_one', 'mini_pc', 'server', 'chromebook',
  'tablet', 'ipad', 'android_tablet',
  'iphone', 'android', 'phone',
  'virtual_machine', 'other',
] as const;

export type DeviceType = (typeof DEVICE_TYPES)[number];
export type DeviceCategory = 'computer' | 'tablet' | 'phone' | 'virtual' | 'other';

const CATEGORY: Record<DeviceType, DeviceCategory> = {
  macbook: 'computer',
  macbook_air: 'computer',
  macbook_pro: 'computer',
  imac: 'computer',
  mac_mini: 'computer',
  mac_studio: 'computer',
  mac_pro: 'computer',
  laptop: 'computer',
  convertible: 'computer',
  desktop: 'computer',
  all_in_one: 'computer',
  mini_pc: 'computer',
  server: 'computer',
  chromebook: 'computer',
  tablet: 'tablet',
  ipad: 'tablet',
  android_tablet: 'tablet',
  iphone: 'phone',
  android: 'phone',
  phone: 'phone',
  virtual_machine: 'virtual',
  other: 'other',
};

export function categoryOf(type: DeviceType): DeviceCategory {
  return CATEGORY[type];
}

export function isDeviceType(value: unknown): value is DeviceType {
  return typeof value === 'string' && (DEVICE_TYPES as readonly string[]).includes(value);
}

// Order matters: "macbookpro" before "macbook", and "macbook" before "macpro".
const MAC_FAMILIES: Array<[string, DeviceType]> = [
  ['macbookpro', 'macbook_pro'],
  ['macbookair', 'macbook_air'],
  ['macbook', 'macbook'],
  ['imac', 'imac'],
  ['macmini', 'mac_mini'],
  ['macstudio', 'mac_studio'],
  ['macpro', 'mac_pro'],
];

/** "MacBook Pro (14-inch, M3)" or "MacBookPro16,1" → macbook_pro; null for anything else. */
export function macFamily(name: string): DeviceType | null {
  const compact = name.toLowerCase().replace(/\s+/g, '');
  for (const [needle, type] of MAC_FAMILIES) {
    if (compact.includes(needle)) return type;
  }
  return null;
}

// SMBIOS type 3 "System Enclosure" chassis types (DMTF DSP0134, 7.4.1).
const CHASSIS: Record<number, DeviceType> = {
  3: 'desktop', // Desktop
  4: 'desktop', // Low Profile Desktop
  5: 'desktop', // Pizza Box
  6: 'desktop', // Mini Tower
  7: 'desktop', // Tower
  15: 'desktop', // Space-saving
  16: 'desktop', // Lunch Box
  8: 'laptop', // Portable
  9: 'laptop', // Laptop
  10: 'laptop', // Notebook
  14: 'laptop', // Sub Notebook
  13: 'all_in_one', // All in One
  31: 'convertible', // Convertible
  30: 'tablet', // Tablet
  32: 'tablet', // Detachable
  11: 'tablet', // Hand Held
  35: 'mini_pc', // Mini PC
  36: 'mini_pc', // Stick PC
  17: 'server', // Main Server Chassis
  23: 'server', // Rack Mount Chassis
  25: 'server', // Multi-system chassis
  28: 'server', // Blade
  29: 'server', // Blade Enclosure
};

// SMBIOS "<manufacturer> <product>" of common hypervisors. Never the CPUID
// hypervisor bit: Windows sets it on bare metal whenever VBS / Memory
// Integrity is on.
const HYPERVISORS = [
  /\bvmware\b/i,
  /\binnotek\b/i,
  /\bvirtualbox\b/i,
  /\bqemu\b/i,
  /\bkvm\b/i,
  /\bxen\b/i,
  /\bparallels\b/i,
  /^microsoft corporation virtual machine\b/i, // Hyper-V
  /^amazon ec2\b/i,
  /\bgoogle compute engine\b/i,
  /\butm\b/i,
];

export function isHypervisorModel(modelIdentifier: string): boolean {
  return HYPERVISORS.some((pattern) => pattern.test(modelIdentifier));
}

function byBattery(d: DeviceInfo): DeviceType {
  return d.formFactor === 'laptop' ? 'laptop' : 'desktop';
}

export function detectDeviceType(d: DeviceInfo): DeviceType {
  if (d.virtual) return 'virtual_machine';

  if (d.platform === 'macos') {
    if (/^virtualmac/i.test(d.modelIdentifier)) return 'virtual_machine';
    // Apple silicon: hw.model is "Mac14,3", so the marketing name decides.
    // Intel: hw.model is "MacBookPro16,1". Check both.
    return macFamily(`${d.model} ${d.modelIdentifier}`) ?? byBattery(d);
  }

  // Windows (and Linux later): modelIdentifier is "<manufacturer> <product>".
  if (isHypervisorModel(d.modelIdentifier)) return 'virtual_machine';

  // Boot Camp: a Mac running Windows still reports its family.
  if (/^apple inc\.?\s/i.test(d.modelIdentifier)) {
    const family = macFamily(d.modelIdentifier.replace(/^apple inc\.?\s+/i, ''));
    if (family) return family;
  }

  const fromChassis = d.chassisType != null ? CHASSIS[d.chassisType] : undefined;
  if (!fromChassis) return byBattery(d);
  // Some OEM boards report "Desktop" on laptops; the battery tells the truth.
  if (fromChassis === 'desktop' && d.formFactor === 'laptop') return 'laptop';
  return fromChassis;
}
