import { describe, expect, it } from 'vitest';

import { categoryOf, DEVICE_TYPES, detectDeviceType, isDeviceType, type DeviceType } from '../src/main/device-type';
import type { DeviceInfo } from '../src/main/keystore';
import { deviceTypeLabel } from '../src/renderer/labels';
import catalogue from './fixtures/device-types.json';

function mac(model: string, modelIdentifier: string, formFactor: DeviceInfo['formFactor'] = 'unknown', extra: Partial<DeviceInfo> = {}): DeviceInfo {
  return { platform: 'macos', osVersion: '15.1.0', model, modelIdentifier, formFactor, hostname: 'Mac', hardwareIdHash: '', chassisType: null, virtual: false, ...extra };
}

function pc(modelIdentifier: string, chassisType: number | null, formFactor: DeviceInfo['formFactor'] = 'unknown', extra: Partial<DeviceInfo> = {}): DeviceInfo {
  return { platform: 'windows', osVersion: '10.0.26100', model: modelIdentifier, modelIdentifier, formFactor, hostname: 'PC', hardwareIdHash: '', chassisType, virtual: false, ...extra };
}

describe('catalogue', () => {
  it('matches the shared fixture the package also tests against', () => {
    expect([...DEVICE_TYPES]).toEqual(catalogue.types.map((t) => t.type));
    for (const { type, category } of catalogue.types) expect(categoryOf(type as DeviceType)).toBe(category);
  });

  it('labels every type', () => {
    for (const type of DEVICE_TYPES) expect(deviceTypeLabel(type)).not.toBe('');
    expect(deviceTypeLabel(null)).toBe('Other device');
  });

  it('recognises only catalogue values', () => {
    expect(isDeviceType('mac_mini')).toBe(true);
    expect(isDeviceType('mobile')).toBe(false);
    expect(isDeviceType(undefined)).toBe(false);
  });
});

describe('macOS', () => {
  it.each<[string, string, DeviceType]>([
    // Apple silicon: the identifier says nothing, the marketing name decides.
    ['MacBook Pro (14-inch, M3)', 'Mac15,3', 'macbook_pro'],
    ['MacBook Air (15-inch, M2)', 'Mac14,15', 'macbook_air'],
    ['Mac mini (2023)', 'Mac14,3', 'mac_mini'],
    ['Mac mini (2024)', 'Mac16,10', 'mac_mini'],
    ['Mac Studio (2023)', 'Mac14,13', 'mac_studio'],
    ['Mac Pro (2023)', 'Mac14,8', 'mac_pro'],
    ['iMac (24-inch, 2023)', 'Mac15,4', 'imac'],
    // Intel: no product name, the identifier decides.
    ['', 'MacBookPro16,1', 'macbook_pro'],
    ['', 'MacBookAir10,1', 'macbook_air'],
    ['', 'MacBook10,1', 'macbook'],
    ['', 'iMacPro1,1', 'imac'],
    ['', 'iMac20,1', 'imac'],
    ['', 'Macmini9,1', 'mac_mini'],
    ['', 'MacPro7,1', 'mac_pro'],
  ])('%s %s → %s', (model, id, expected) => {
    expect(detectDeviceType(mac(model, id))).toBe(expected);
  });

  it('falls back to the battery for a model it does not know', () => {
    expect(detectDeviceType(mac('Mac Something (2030)', 'Mac99,1', 'laptop'))).toBe('laptop');
    expect(detectDeviceType(mac('Mac Something (2030)', 'Mac99,1', 'desktop'))).toBe('desktop');
  });

  it('detects virtual machines', () => {
    expect(detectDeviceType(mac('', 'VirtualMac2,1'))).toBe('virtual_machine');
    expect(detectDeviceType(mac('MacBook Pro', 'Mac15,3', 'laptop', { virtual: true }))).toBe('virtual_machine');
  });
});

describe('Windows', () => {
  it.each<[number, DeviceType]>([
    [3, 'desktop'], [4, 'desktop'], [5, 'desktop'], [6, 'desktop'], [7, 'desktop'], [15, 'desktop'], [16, 'desktop'],
    [8, 'laptop'], [9, 'laptop'], [10, 'laptop'], [14, 'laptop'],
    [13, 'all_in_one'],
    [31, 'convertible'],
    [30, 'tablet'], [32, 'tablet'], [11, 'tablet'],
    [35, 'mini_pc'], [36, 'mini_pc'],
    [17, 'server'], [23, 'server'], [25, 'server'], [28, 'server'], [29, 'server'],
  ])('chassis %i → %s', (chassis, expected) => {
    expect(detectDeviceType(pc('LENOVO 21CB', chassis))).toBe(expected);
  });

  it('falls back to the battery for Other, Unknown and missing chassis types', () => {
    expect(detectDeviceType(pc('LENOVO 21CB', 1, 'laptop'))).toBe('laptop');
    expect(detectDeviceType(pc('LENOVO 21CB', 2, 'desktop'))).toBe('desktop');
    expect(detectDeviceType(pc('LENOVO 21CB', null, 'unknown'))).toBe('desktop');
  });

  it('trusts the battery over a "Desktop" chassis on a laptop', () => {
    expect(detectDeviceType(pc('ACME Book 14', 3, 'laptop'))).toBe('laptop');
  });

  it('reports a Mac running Windows (Boot Camp) as its Mac family', () => {
    expect(detectDeviceType(pc('Apple Inc. MacBookPro16,1', 10, 'laptop'))).toBe('macbook_pro');
    expect(detectDeviceType(pc('Apple Inc. iMac19,1', 13))).toBe('imac');
  });

  it.each([
    'VMware, Inc. VMware7,1',
    'innotek GmbH VirtualBox',
    'QEMU Standard PC (Q35 + ICH9, 2009)',
    'Red Hat KVM',
    'Xen HVM domU',
    'Parallels International GmbH. Parallels ARM Virtual Machine',
    'Microsoft Corporation Virtual Machine',
    'Amazon EC2 t3.micro',
    'Google Google Compute Engine',
  ])('detects the hypervisor in "%s"', (id) => {
    expect(detectDeviceType(pc(id, 1))).toBe('virtual_machine');
  });

  it('does not mistake real Microsoft hardware for Hyper-V', () => {
    expect(detectDeviceType(pc('Microsoft Corporation Surface Pro 9', 32))).toBe('tablet');
    expect(detectDeviceType(pc('Microsoft Corporation Surface Laptop 5', 10))).toBe('laptop');
  });

  it('detects a VM from the SMBIOS flag alone', () => {
    expect(detectDeviceType(pc('ACME Desktop', 3, 'desktop', { virtual: true }))).toBe('virtual_machine');
  });
});
