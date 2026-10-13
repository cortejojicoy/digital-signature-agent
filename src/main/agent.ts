// Composes the key store, storage, pairing and jobs. The Electron shell
// (index.ts) drives this; tests drive it directly with a software key store
// and a mock server.
import { X509Certificate } from 'node:crypto';

import { AgentApi, ApiError, type Credentials, type FetchLike } from './api';
import {
  CertificateError,
  certificateErrorFrom,
  describeChain,
  newCertificateIds,
  type CertificateDescription,
  type CertificateStore,
  type StoredCertificate,
} from './certificates';
import { detectDeviceType, isDeviceType, type DeviceType } from './device-type';
import { JobRunner, type ConfirmRequest, type JobOutcome } from './jobs';
import type { Algorithm, Capabilities, KeySource, KeyStore } from './keystore';
import { deleteKeys, pair, PairingError, type PairOptions } from './pairing';
import { normalizeOrigin, normalizeUserCode, parseLink, type OriginPolicy, type PairLink, type PresenceLink } from './protocol';
import { keySourceOf, ownedKeyIds, type PairedServer, type PendingRevoke, type Store } from './store';

export interface AgentOptions extends OriginPolicy {
  keystore: KeyStore;
  store: Store;
  agentVersion: string;
  fetch?: FetchLike;
  biometryOnly?: boolean;
  pollIntervalMs?: number;
  /** Imported PKCS#12 certificates (pkcs12-key-storage-plan.md §6.2). Without it, no certificate features. */
  certificates?: CertificateStore;
  /** The chosen key storage (settings). Without it, pairings use the platform key. */
  keyStorage?(): KeySource | null;
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
  keySource: KeySource;
  /** keySource 'pkcs12': the certificate's name, e.g. "Test UP 4". */
  certificateName?: string;
}

/** What the import screen previews (pkcs12-key-storage-plan.md §7.2). */
export interface CertificatePreview extends CertificateDescription {
  algorithm: Algorithm;
  keyBits: number;
  /** This certificate is already imported here. */
  alreadyImported: boolean;
}

export interface CertificateSummary extends StoredCertificate {
  /** The newest certificate, which new certificate pairings use. */
  active: boolean;
  /** Names of the apps paired with it. */
  usedBy: string[];
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
      certificateName: (server) => this.certificateOf(server)?.commonName,
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
      keySource: keySourceOf(s),
      certificateName: this.certificateOf(s)?.commonName,
    }));
  }

  // ── Software certificates (pkcs12-key-storage-plan.md §6.2–6.6) ──

  /** Imported certificates, oldest first, with the apps that use each. */
  certificateSummaries(): CertificateSummary[] {
    const store = this.options.certificates;
    if (!store) return [];
    const active = store.active()?.id;
    const servers = this.options.store.list();
    return store.list().map((c) => ({
      ...c,
      active: c.id === active,
      usedBy: servers.filter((s) => s.certificateId === c.id).map((s) => s.name),
    }));
  }

  /** Opens a .p12 for the preview. Imports nothing. Throws CertificateError. */
  async inspectCertificate(data: Buffer, password: string): Promise<CertificatePreview> {
    await this.requireCertificateSupport();
    try {
      const contents = await this.options.keystore.inspectPkcs12(data, password);
      const description = describeChain(contents.chain);
      return {
        ...description,
        algorithm: contents.algorithm,
        keyBits: contents.keyBits,
        alreadyImported: this.options.certificates?.findByFingerprint(description.fingerprint256) != null,
      };
    } catch (err) {
      throw certificateErrorFrom(err);
    }
  }

  /**
   * Imports a .p12's key, non-exportable, and makes it the active
   * certificate. On macOS this seals it to the Secure Enclave; signing then
   * needs Touch ID or the password. Older certificates that no pairing uses
   * any more are removed (§6.6).
   */
  async importCertificate(data: Buffer, password: string): Promise<StoredCertificate> {
    const store = await this.requireCertificateSupport();
    let description: CertificateDescription;
    try {
      description = describeChain((await this.options.keystore.inspectPkcs12(data, password)).chain);
    } catch (err) {
      throw certificateErrorFrom(err);
    }

    // The same certificate again: make it the active one, keep its key.
    const existing = store.findByFingerprint(description.fingerprint256);
    if (existing && (await this.options.keystore.findKey(existing.keyId))) {
      await store.remove(existing.id);
      await store.save(existing);
      await this.pruneCertificates();
      this.options.onServersChanged?.();
      return existing;
    }

    const { id, keyId } = newCertificateIds();
    let imported;
    try {
      imported = await this.options.keystore.importPkcs12({
        keyId,
        data,
        password,
        requireUserPresence: true,
        biometryOnly: this.options.biometryOnly,
      });
    } catch (err) {
      throw certificateErrorFrom(err);
    }
    const leafSpki = new X509Certificate(description.chain[0]).publicKey.export({ format: 'der', type: 'spki' });
    if (!imported.key.spki.equals(leafSpki)) {
      await deleteKeys(this.options.keystore, [keyId]);
      throw new CertificateError('E_KEY_MISMATCH', "The private key in this file doesn't belong to its certificate.");
    }

    const certificate: StoredCertificate = {
      id,
      keyId,
      subject: description.subject,
      commonName: description.commonName,
      organization: description.organization,
      issuer: description.issuer,
      issuerName: description.issuerName,
      serialHex: description.serialHex,
      notBefore: description.notBefore,
      notAfter: description.notAfter,
      fingerprint256: description.fingerprint256,
      chain: description.chain.map((der) => der.toString('base64')),
      algorithm: imported.key.algorithm,
      protection: imported.key.protection,
      userPresence: imported.key.userPresence,
      pnpki: description.pnpki,
      importedAt: new Date().toISOString(),
    };
    if (existing) await store.remove(existing.id); // its key was gone
    await store.save(certificate);
    await this.pruneCertificates();
    this.options.onServersChanged?.();
    return certificate;
  }

  /** Deletes a certificate and its key. Refused while an app is paired with it (§6.5). */
  async removeCertificate(id: string): Promise<void> {
    const store = await this.requireCertificateSupport();
    const certificate = store.get(id);
    if (!certificate) throw new CertificateError('not_found', 'That certificate is no longer here.');
    const usedBy = this.options.store.list().filter((s) => s.certificateId === id);
    if (usedBy.length > 0) {
      const names = usedBy.map((s) => s.name).join(', ');
      throw new CertificateError('in_use', `Unpair ${names} first: ${usedBy.length === 1 ? 'it signs' : 'they sign'} with this certificate.`);
    }
    await deleteKeys(this.options.keystore, [certificate.keyId]);
    await store.remove(id);
    this.options.onServersChanged?.();
  }

  /** Older certificates go once no pairing uses them; the active one stays (§6.6). */
  private async pruneCertificates(): Promise<void> {
    const store = this.options.certificates;
    if (!store) return;
    const active = store.active()?.id;
    const inUse = new Set(this.options.store.list().map((s) => s.certificateId));
    for (const certificate of store.list()) {
      if (certificate.id === active || inUse.has(certificate.id)) continue;
      await deleteKeys(this.options.keystore, [certificate.keyId]);
      await store.remove(certificate.id);
    }
  }

  private certificateOf(server: PairedServer): StoredCertificate | null {
    return server.certificateId ? (this.options.certificates?.get(server.certificateId) ?? null) : null;
  }

  private async requireCertificateSupport(): Promise<CertificateStore> {
    const store = this.options.certificates;
    if (!store || !(await this.options.keystore.capabilities()).pkcs12) {
      throw new CertificateError(
        'E_UNSUPPORTED',
        process.platform === 'darwin'
          ? 'Importing a certificate needs macOS 15 or later.'
          : "Importing a certificate isn't supported on this computer.",
      );
    }
    return store;
  }

  /**
   * Asks each paired app for the account's other devices (§7.4). Best
   * effort and throttled: the status window calls it whenever it opens.
   * Resolves true when the other devices changed.
   *
   * Also picks up the account's name: a hub account has none when it pairs,
   * and gets one once the person identifies themselves. A new name is
   * stored and reported through onServersChanged.
   */
  async refreshOtherDevices(force = false): Promise<boolean> {
    if (!force && Date.now() - this.otherDevicesAt < OTHER_DEVICES_TTL_MS) return false;
    this.otherDevicesAt = Date.now();
    let changed = false;
    let renamed = false;
    for (const server of this.options.store.list()) {
      try {
        const status = await this.apiFor(server.origin).status(this.credentialsFor(server));
        const name = status.user?.name;
        if (typeof name === 'string' && name.trim() !== '' && name !== server.userName) {
          await this.options.store.update({ ...server, userName: name });
          renamed = true;
        }
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
    if (renamed) this.options.onServersChanged?.();
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

    const certificate = this.pairingCertificate();

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
        certificate,
        pollIntervalMs: this.options.pollIntervalMs,
      },
      code,
      opts,
    );
    await this.pruneCertificates(); // a re-pair may have left an old certificate unused
    this.options.onServersChanged?.();
    return paired;
  }

  /** The certificate new pairings use, or null for a platform key (§6.4). */
  private pairingCertificate(): StoredCertificate | null {
    // No keyStorage option at all (tests, older callers): the platform key.
    const storage = this.options.keyStorage ? this.options.keyStorage() : 'platform';
    if (storage === null) {
      throw new PairingError('no_key_storage', 'Choose where your signing key lives first.');
    }
    if (storage === 'platform') return null;
    const certificate = this.options.certificates?.active() ?? null;
    if (!certificate) throw new PairingError('certificate_missing', 'Import your certificate first.');
    return certificate;
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
    const outcome = link.kind === 'login' ? await this.jobs.handleLogin(link) : await this.jobs.handle(link);
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
        // Keep only the session key: it authenticates the retry, and can't
        // sign documents. A certificate's key stays with the certificate (§6.5).
        await deleteKeys(
          this.options.keystore,
          ownedKeyIds(server).filter((keyId) => keyId !== server.sessionKeyId),
        );
        await this.options.store.remove(server.id);
        this.otherDevices.delete(server.id);
        await this.pruneCertificates();
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
    await deleteKeys(this.options.keystore, ownedKeyIds(server));
    await this.options.store.remove(server.id);
    this.otherDevices.delete(server.id);
    await this.pruneCertificates();
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
