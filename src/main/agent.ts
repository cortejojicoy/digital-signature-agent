// Composes the key store, storage, pairing and jobs. The Electron shell
// (index.ts) drives this; tests drive it directly with a software key store
// and a mock server.
import { AgentApi, ApiError, type Credentials, type FetchLike } from './api';
import { detectDeviceType, isDeviceType, type DeviceType } from './device-type';
import { JobRunner, type ConfirmRequest, type JobOutcome } from './jobs';
import type { Capabilities, KeyStore } from './keystore';
import { deleteKeys, pair, type PairOptions } from './pairing';
import { normalizeOrigin, normalizeUserCode, parseLink, type OriginPolicy, type PairLink, type PresenceLink } from './protocol';
import type { PairedServer, PendingRevoke, Store } from './store';

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
  insecure: boolean;
  deviceType: DeviceType;
  /** The same account's other signing devices, as the server last reported them (§7.4). */
  otherDevices: Array<{ label: string; deviceType: DeviceType | null }>;
}

/** What unpair() did (one-computer-per-account-plan.md §7.1). */
export type UnpairResult =
  /** The server revoked the device, or had already: the server and this computer agree. */
  | { status: 'unpaired' }
  /** The server couldn't be reached and nothing changed: ask before removing locally. */
  | { status: 'unreachable'; serverName: string }
  /** Removed here anyway: the signing key is gone, and the revoke is queued. */
  | { status: 'removed_locally' };

export interface PendingRevokeSummary {
  origin: string;
  serverName: string;
  queuedAt: string;
}

const OTHER_DEVICES_TTL_MS = 60_000;

export class Agent {
  readonly jobs: JobRunner;
  private localNetwork: boolean;
  private localType: Promise<DeviceType> | null = null;
  private readonly otherDevices = new Map<string, ServerSummary['otherDevices']>();
  private otherDevicesAt = 0;

  constructor(private readonly options: AgentOptions) {
    this.localNetwork = options.allowInsecureLocalNetwork === true;
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

  /** Developer mode: plain http:// to local-network apps (protocol.ts). */
  setAllowInsecureLocalNetwork(on: boolean): void {
    this.localNetwork = on;
  }

  private get policy(): OriginPolicy {
    return { allowInsecureLocalNetwork: this.localNetwork };
  }

  apiFor(origin: string): AgentApi {
    if (origin.startsWith('http:') && !this.localNetwork) {
      throw new Error(`${origin} uses plain HTTP. Turn on Developer mode to use it.`);
    }
    return new AgentApi({
      origin,
      agentVersion: this.options.agentVersion,
      fetch: this.options.fetch,
      ...this.policy,
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

  /**
   * Start-up housekeeping: give pairings made before device types existed a
   * type (§5), and retry revokes left over from an offline unpair (§7.3).
   */
  async init(): Promise<void> {
    const untyped = this.options.store.list().filter((s) => !s.deviceType);
    if (untyped.length > 0) {
      const type = await this.thisDeviceType();
      for (const server of untyped) await this.options.store.update({ ...server, deviceType: type });
      this.options.onServersChanged?.();
    }
    await this.retryRevokes();
  }

  /** What this computer is, detected once per run. */
  thisDeviceType(): Promise<DeviceType> {
    this.localType ??= this.options.keystore
      .deviceInfo('')
      .then(detectDeviceType)
      .catch((): DeviceType => 'other');
    return this.localType;
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
      insecure: s.origin.startsWith('http:'),
      deviceType: s.deviceType ?? 'other',
      otherDevices: this.otherDevices.get(s.id) ?? [],
    }));
  }

  /**
   * Asks each paired app for the account's other devices (§7.4). Best
   * effort and throttled: the status window calls it whenever it opens.
   * Resolves true when something changed.
   */
  async refreshOtherDevices(force = false): Promise<boolean> {
    if (!force && Date.now() - this.otherDevicesAt < OTHER_DEVICES_TTL_MS) return false;
    this.otherDevicesAt = Date.now();
    let changed = false;
    for (const server of this.options.store.list()) {
      try {
        const status = await this.apiFor(server.origin).status(this.credentialsFor(server));
        const others = (status.other_devices ?? []).map((d) => ({
          label: String(d.label ?? ''),
          deviceType: isDeviceType(d.device_type) ? d.device_type : null,
        }));
        if (JSON.stringify(others) !== JSON.stringify(this.otherDevices.get(server.id) ?? [])) changed = true;
        this.otherDevices.set(server.id, others);
      } catch (err) {
        if (err instanceof ApiError && err.unauthorized) {
          await this.forget(server);
          changed = true;
        }
      }
    }
    return changed;
  }

  async pair(originInput: string, codeInput: string, opts: PairOptions = {}): Promise<PairedServer> {
    const origin = normalizeOrigin(originInput, this.policy);
    if (!origin) {
      throw new Error(
        this.localNetwork
          ? 'Enter an HTTPS or local network address, e.g. http://192.168.1.20:8000'
          : 'Enter an HTTPS address, e.g. https://sign.example.gov.ph',
      );
    }
    const code = normalizeUserCode(codeInput);
    if (!code) throw new Error('Enter the 8-character code, e.g. K7QM-2XPD');

    // An unpair that never reached this server still holds the computer
    // there; finish it first, or a different account would be refused.
    await this.retryRevokes(origin);

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
    const link = parseLink(raw, this.policy);
    if (!link) return null;
    if (link.kind === 'pair') {
      this.options.onPairLink?.(link);
      return null;
    }
    if (link.kind === 'presence') {
      await this.reportPresence(link);
      return null;
    }
    const outcome = await this.jobs.handle(link);
    this.options.onJobOutcome?.(outcome);
    return outcome;
  }

  /**
   * Answers a presence check, silently: no window, no OS prompt. The web
   * page only learns "the paired computer is here" from the server, which
   * checks the account; a server this computer isn't paired with is ignored.
   */
  private async reportPresence(link: PresenceLink): Promise<void> {
    const server = this.options.store.get(link.serverId);
    if (!server) return;
    try {
      await this.apiFor(server.origin).reportPresence(this.credentialsFor(server), link.checkId, link.token);
    } catch {
      // Nothing to tell the user here: the page waiting on the check says
      // what happened (another account, expired check).
    }
  }

  /**
   * Revokes the device on the server, then deletes the local keys. The
   * server goes first, so the user knows whether it heard
   * (one-computer-per-account-plan.md §7.1):
   *
   * - accepted, or 401 (already revoked on the web): `unpaired`.
   * - anything else, by default: nothing changes, `unreachable`. The UI asks.
   * - anything else, with `offline: 'remove'`: the pairing goes away here at
   *   once, the signing key with it, and the revoke is queued and retried
   *   (§7.3). Until it lands the server still counts this computer, so the
   *   account can't pair another one. `removed_locally`.
   *
   * Never refuses outright: that would leave the signing key on a computer
   * someone is trying to leave.
   */
  async unpair(serverId: string, opts: { offline?: 'ask' | 'remove' } = {}): Promise<UnpairResult> {
    const server = this.options.store.get(serverId);
    if (!server) return { status: 'unpaired' };
    const token = this.options.store.token(server.id);
    try {
      await this.apiFor(server.origin).unpair(this.credentialsFor(server));
    } catch (err) {
      const alreadyGone = err instanceof ApiError && err.unauthorized;
      if (!alreadyGone && token) {
        if (opts.offline !== 'remove') return { status: 'unreachable', serverName: server.name };
        await this.options.store.queueRevoke(
          {
            serverId: server.id,
            origin: server.origin,
            userId: server.userId,
            deviceUuid: server.deviceUuid,
            sessionKeyId: server.sessionKeyId,
            queuedAt: new Date().toISOString(),
            serverName: server.name,
          },
          token,
        );
        // Keep only the session key: it authenticates the retry, and can't sign documents.
        await deleteKeys(this.options.keystore, [server.identityKeyId]);
        await this.options.store.remove(server.id);
        this.otherDevices.delete(server.id);
        this.options.onServersChanged?.();
        return { status: 'removed_locally' };
      }
    }
    await this.forget(server);
    return { status: 'unpaired' };
  }

  /** Unpairs the server hasn't heard about yet, for the status window. Never includes tokens. */
  pendingRevokes(): PendingRevokeSummary[] {
    return this.options.store.pendingRevokes().map((r) => ({
      origin: r.origin,
      serverName: r.serverName || hostOf(r.origin),
      queuedAt: r.queuedAt,
    }));
  }

  /**
   * Retries queued revokes, optionally only those for one origin. A revoke is
   * done when the server accepts it, or answers 401 (already revoked on the
   * web, or by an admin). Anything else is left for the next try.
   */
  async retryRevokes(origin?: string): Promise<void> {
    let changed = false;
    for (const revoke of this.options.store.pendingRevokes()) {
      if (origin !== undefined && revoke.origin !== origin) continue;
      const token = this.options.store.revokeToken(revoke.deviceUuid);
      // A token that no longer decrypts can never authenticate: give up on it.
      if (token) {
        try {
          await this.apiFor(revoke.origin).unpair(this.revokeCredentials(revoke, token));
        } catch (err) {
          if (!(err instanceof ApiError && err.unauthorized)) continue;
        }
      }
      await deleteKeys(this.options.keystore, [revoke.sessionKeyId]);
      await this.options.store.dropRevoke(revoke.deviceUuid);
      changed = true;
    }
    if (changed) this.options.onServersChanged?.();
  }

  private revokeCredentials(revoke: PendingRevoke, token: string): Credentials {
    return {
      token,
      userId: revoke.userId,
      signWithSessionKey: (message) => this.options.keystore.sign(revoke.sessionKeyId, message, 'authenticate with the server'),
    };
  }

  private async forget(server: PairedServer): Promise<void> {
    await deleteKeys(this.options.keystore, [server.identityKeyId, server.sessionKeyId]);
    await this.options.store.remove(server.id);
    this.otherDevices.delete(server.id);
    this.options.onServersChanged?.();
  }
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}
