// Agent preferences (settings.json in userData). Nothing secret lives here.
import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { KeySource } from './keystore';
import { readJson, writeJsonAtomic } from './store';

export interface Settings {
  /** Allow plain http:// to local-network apps, for testing (protocol.ts). */
  developerMode: boolean;
  /**
   * Where new pairings' signing keys live, chosen on first launch
   * (pkcs12-key-storage-plan.md §6.1). null until the user chooses.
   */
  keyStorage: KeySource | null;
}

const DEFAULTS: Settings = { developerMode: false, keyStorage: null };
const KEY_STORAGES: ReadonlySet<unknown> = new Set(['platform', 'pkcs12']);

export class SettingsStore {
  private current: Settings = { ...DEFAULTS };

  constructor(private readonly dir: string) {}

  async load(): Promise<Settings> {
    const saved = await readJson<Partial<Settings>>(this.file());
    this.current = {
      developerMode: saved?.developerMode === true,
      keyStorage: KEY_STORAGES.has(saved?.keyStorage) ? (saved!.keyStorage as KeySource) : null,
    };
    return this.get();
  }

  get(): Settings {
    return { ...this.current };
  }

  async update(patch: Partial<Settings>): Promise<Settings> {
    this.current = { ...this.current, ...patch };
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    await writeJsonAtomic(this.file(), this.current);
    return this.get();
  }

  private file(): string {
    return path.join(this.dir, 'settings.json');
  }
}
