// Composes the key store, storage, pairing and jobs. The Electron shell
// (index.ts) drives this; tests drive it directly with a software key store
// and a mock server.
import { AgentApi, type Credentials, type FetchLike } from './api';
import { JobRunner, type ConfirmRequest, type JobOutcome } from './jobs';
import type { Capabilities, KeyStore } from './keystore';
import { deleteKeys, pair, type PairOptions } from './pairing';
import { normalizeOrigin, normalizeUserCode, parseLink, type OriginPolicy, type PairLink } from './protocol';
import type { PairedServer, Store } from './store';

export interface AgentOptions extends OriginPolicy {
  keystore: KeyStore;
  store: Store;
  agentVersion: string;
  fetch?: FetchLike;
  biometryOnly?: boolean;
  pollIntervalMs?: number;
  confirm(request: ConfirmRequest): Promise<boolean>;
  parentWindow?(): Buffer | undefined;
  /** A pair link arrived: the UI should show it prefilled for the user to confirm. */
  onPairLink?(link: PairLink): void;
  onJobOutcome?(outcome: JobOutcome): void;
  onServersChanged?(): void;
}

export interface ServerSummary {
  id: string;
  name: string;
  origin: string;
  userName: string;
  deviceLabel: string;
  protection: PairedServer['protection'];
  userPresence: boolean;
  pairedAt: string;
}

export class Agent {
  readonly jobs: JobRunner;

  constructor(private readonly options: AgentOptions) {
    this.jobs = new JobRunner({
      keystore: options.keystore,
      store: options.store,
      apiFor: (server) => this.apiFor(server.origin),
      credentialsFor: (server) => this.credentialsFor(server),
      confirm: options.confirm,
      parentWindow: options.parentWindow,
      onUnauthorized: (server) => void this.forget(server),
    });
  }

  apiFor(origin: string): AgentApi {
    return new AgentApi({
      origin,
      agentVersion: this.options.agentVersion,
      fetch: this.options.fetch,
      allowInsecureLocalhost: this.options.allowInsecureLocalhost,
    });
  }

  credentialsFor(server: PairedServer): Credentials {
    const token = this.options.store.token(server.id);
    if (!token) throw new Error(`no stored token for ${server.origin}`);
    return {
      token,
      userId: server.userId,
      signWithSessionKey: (message) => this.options.keystore.sign(server.sessionKeyId, message, 'authenticate with the server'),
    };
  }

  capabilities(): Promise<Capabilities> {
    return this.options.keystore.capabilities();
  }

  servers(): ServerSummary[] {
    return this.options.store.list().map((s) => ({
      id: s.id,
      name: s.name,
      origin: s.origin,
      userName: s.userName,
      deviceLabel: s.deviceLabel,
      protection: s.protection,
      userPresence: s.userPresence,
      pairedAt: s.pairedAt,
    }));
  }

  async pair(originInput: string, codeInput: string, opts: PairOptions = {}): Promise<PairedServer> {
    const origin = normalizeOrigin(originInput, this.options);
    if (!origin) throw new Error('Enter the HTTPS address of the app, for example https://sign.example.gov.ph');
    const code = normalizeUserCode(codeInput);
    if (!code) throw new Error('Enter the 8-character code shown on the web, for example K7QM-2XPD');

    const paired = await pair(
      {
        keystore: this.options.keystore,
        store: this.options.store,
        api: this.apiFor(origin),
        agentVersion: this.options.agentVersion,
        biometryOnly: this.options.biometryOnly,
        pollIntervalMs: this.options.pollIntervalMs,
      },
      code,
      opts,
    );
    this.options.onServersChanged?.();
    return paired;
  }

  /** Entry point for every kukuxsign:// link. Unknown shapes are dropped. */
  async handleLink(raw: string): Promise<JobOutcome | null> {
    const link = parseLink(raw, this.options);
    if (!link) return null;
    if (link.kind === 'pair') {
      this.options.onPairLink?.(link);
      return null;
    }
    const outcome = await this.jobs.handle(link);
    this.options.onJobOutcome?.(outcome);
    return outcome;
  }

  /** Revokes the token on the server (best effort) and deletes local keys. */
  async unpair(serverId: string): Promise<void> {
    const server = this.options.store.get(serverId);
    if (!server) return;
    // If the server is unreachable, still remove locally; the device can
    // then be revoked from "My signing devices" on the web.
    await Promise.resolve()
      .then(() => this.apiFor(server.origin).unpair(this.credentialsFor(server)))
      .catch(() => {});
    await this.forget(server);
  }

  private async forget(server: PairedServer): Promise<void> {
    await deleteKeys(this.options.keystore, [server.identityKeyId, server.sessionKeyId]);
    await this.options.store.remove(server.id);
    this.options.onServersChanged?.();
  }
}
