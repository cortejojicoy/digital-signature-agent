# Kukux Sign Agent

A desktop signing agent for [`kukux/digital-signature`](../digital-signature).
It creates signing keys inside the machine's security chip (the Secure
Enclave on macOS, the TPM with Windows Hello on Windows), pairs them with the
web app, and proves on each signing that *this* machine was used, with Touch
ID or Windows Hello enforced by the key itself.

Design: [desktop-agent-plan.md](desktop-agent-plan.md). Wire contract for the
server: [How the API works](https://cortejojicoy.github.io/digital-signature-agent/#/how-the-api-works). Docs and full API reference:
[cortejojicoy.github.io/digital-signature-agent](https://cortejojicoy.github.io/digital-signature-agent/)
(source in [docs/](docs/), deployed by [.github/workflows/pages.yml](.github/workflows/pages.yml)).

## Install

```sh
# macOS
curl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash
```

```powershell
# Windows (PowerShell, no admin needed)
irm https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.ps1 | iex
```

The installers verify the download's SHA-512 and code signature, install for
the current user, register `kukuxsign://`, and start the agent. Releases are
**free builds** by default: no paid Apple or Windows signing, with keys still in
the Secure Enclave / TPM. See
[Installation](https://cortejojicoy.github.io/digital-signature-agent/#/installation/free-and-signed) for what
that means, plus manual installs, MDM rollout, self-hosted downloads and
uninstalling.

## Status

| Phase (plan §13) | State |
|---|---|
| 0: spikes | 0a is solved without a paid account: the Secure Enclave works from free, ad-hoc signed builds via CryptoKit (tested on real hardware, including the password prompt). A signed build's keychain route is still untested. 0b (Hello prompt parenting) needs Windows hardware. |
| 1: native module | Done. macOS is built and tested on hardware. Windows compiles and passes its tests on CI (software backend); Hello and TPM still need real hardware. |
| 2: Electron shell | Done. Pairs with and signs against the local mock server. |
| 3–4: package | Not in this repo. Implement [Server integration](https://cortejojicoy.github.io/digital-signature-agent/#/server-integration) in `kukux/digital-signature`. |
| 5: distribution | Free releases work with no secrets. Paid signing switches on per platform when its secrets are added. The free package and both install scripts are tested (macOS locally, both on CI). |

How macOS keys are stored depends on the build:

| Build | Where the key lives |
|---|---|
| Signed (Developer ID + provisioning profile) | Secure Enclave, via the data-protection keychain |
| Free (ad-hoc signed) | Secure Enclave, via CryptoKit: an SE-wrapped blob in `<userData>/keys`, usable only by this Mac's chip |
| Mac without a Secure Enclave | Non-exportable software key, shown as *Software key · lower assurance* |

Free macOS builds also keep Chromium and the agent's tokens out of the
keychain. The keychain ties access to the code signature, and an ad-hoc
signature changes with every build, so otherwise macOS would ask for a password
after each update. Tokens are sealed to the Secure Enclave instead (ECDH +
AES-GCM).

## Layout

```
native/                  keystore.node (N-API, C++ / Objective-C++)
  include/keystore.h     platform-neutral interface (§4.1)
  src/addon.cc           async N-API binding (§4.2)
  src/common/            SPKI wrapping, raw→DER ECDSA, salted hardware hash
  src/mac/               Secure Enclave (keychain + CryptoKit/Swift), device info (§5)
  src/win/               Windows Hello, TPM + software CNG, device info (§6)
  test/                  native tests (node --test)
src/main/                Electron main process
  agent.ts               composes everything below
  keystore.ts            typed addon wrapper
  canonical.ts           proof messages (shared vectors with PHP)
  protocol.ts            kukuxsign:// link parsing
  api.ts                 HTTPS client: pinned origin, bearer + X-Agent-Proof
  pairing.ts, jobs.ts    §8.1 and §8.3 flows
  store.ts               servers.json + tokens (safeStorage, or SE-sealed on free macOS)
  build-info.ts          free vs signed build flags
  index.ts, updater.ts   lifecycle, tray, windows, hardening, IPC
src/preload/             contextBridge API (no generic sign)
src/renderer/            React UI: status, pairing, confirm
test/                    vitest: unit + end-to-end against test/support/mock-server.ts
```

## Development

Requirements: Node ≥ 22.18. On macOS, Xcode Command Line Tools (for clang and
swiftc). On Windows,
Visual Studio 2022 with the C++ workload and Windows 10/11 SDK (C++/WinRT
headers).

```sh
npm install
npm run build:native        # native/build/Release/keystore.node (this Mac's arch)
npm run rebuild:native      # release build: universal on macOS
npm run test:native         # software backend; KUKUX_KEYSTORE_BACKEND=auto for hardware
npm test                    # vitest: canonical vectors, links, API, store, end-to-end
npm run typecheck
```

Run the app against the local mock server:

```sh
npm run mock-server         # prints an origin, a pairing code and a pair link
npm run dev                 # builds and starts Electron
```

Then pair with the printed origin and code, and confirm with the printed
`curl … /confirm`. Create a job with `curl -X POST <origin>/__dev/jobs` and
open the returned `kukuxsign://job/…` link.

### Testing against a local project

Turn on **Developer mode** in the agent window (it's always on under
`npm run dev`; installed builds ask for confirmation and default to off). It
lets the agent accept plain `http://` for local addresses: `localhost`,
`127.x`, `[::1]`, private LAN IPs (`10.x`, `172.16–31.x`, `192.168.x`,
link-local), and `*.local`, `*.test`, `*.localhost` names. Public addresses
stay HTTPS-only. In Developer mode the agent also trusts the OS certificate
store, so Herd / Valet / mkcert HTTPS works too. Turning it off stops
HTTP pairings from working until it's back on; they're marked **HTTP**.

- **Same machine:** `php artisan serve` with `APP_URL=http://127.0.0.1:8000`,
  or Herd (`http://my-app.test`, or `herd secure` for HTTPS). Enter that exact
  address in the agent.
- **Another machine on the same network:** on the server machine, run
  `php artisan serve --host=0.0.0.0 --port=8000` with
  `APP_URL=http://<LAN-IP>:8000`, and allow port 8000 through its firewall.
  Open the web app in the browser on the agent machine at that same address,
  and turn on Developer mode there (or use `npm run dev`). To try this without Laravel, run
  `npm run mock-server -- --lan`, which binds to every interface and prints
  the LAN address.

The address must match the server's `APP_URL` exactly, or pairing fails with
`origin_mismatch` (`localhost` and `127.0.0.1` count as different). Request
proofs allow ±60 s of clock difference, so keep both machines' clocks synced.
On macOS 15+, allow the agent when it asks for Local Network access. On plain
HTTP the agent token and job details travel unencrypted over the network, so
use this for testing only.

> Running inside VS Code's terminal? It may export `ELECTRON_RUN_AS_NODE=1`,
> which makes Electron start as plain Node. Use `env -u ELECTRON_RUN_AS_NODE npm run dev`.

Environment switches:

| Variable | Effect |
|---|---|
| `KUKUX_KEYSTORE_BACKEND=software` | Force software keys (CI) |
| `KUKUX_KEYSTORE_DEBUG=1` | Log why hardware key creation fell back (macOS) |
| `KUKUX_BIOMETRY_ONLY=1` | macOS: require biometrics (`BiometryCurrentSet`) instead of biometrics-or-password |

## Release builds

Push a `v<version>` tag (`git tag v1.2.0 && git push origin v1.2.0`). The
version comes from the tag: the workflow stamps it into `package.json` before
building, so there's no need to bump `package.json` by hand.
[.github/workflows/release.yml](.github/workflows/release.yml) builds both
platforms into a draft release, attaches `install.sh` / `install.ps1`, and then
publishes it. **No secrets are needed**: without them you get a free build.

Optional paid signing is decided per platform. Once all of a platform's
secrets are in the `release` environment, that platform is signed and the
install scripts pin the signer:
- macOS: `MAC_CSC_LINK`, `MAC_CSC_KEY_PASSWORD`, `MAC_PROVISIONING_PROFILE_B64`,
  `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`.
- Windows: `WIN_CSC_LINK`, `WIN_CSC_KEY_PASSWORD`, plus the `WIN_PUBLISHER_NAME`
  variable.

Set the `REQUIRE_SIGNED_RELEASE=true` variable to make a release fail rather
than fall back to a free build.

Locally:

```sh
npm run dist:mac            # needs Developer ID + provisioning profile + notarization credentials
npm run dist:win            # needs an Authenticode signing setup
npm run dist:local          # free build, the same as a release without secrets
```

On macOS, `rebuild:native` produces a universal (arm64 + x86_64)
`keystore.node`, so the arm64 and x64 packages both load it.

If you later add paid macOS signing:

1. Register the App ID `com.kukux.signagent` with a keychain access group.
2. Create a **Developer ID** provisioning profile for it. The workflow reads it
   from `MAC_PROVISIONING_PROFILE_B64` and fills `TEAMID` in
   [build/entitlements.mac.plist](build/entitlements.mac.plist) from `APPLE_TEAM_ID`.
3. Check on real hardware that the status view shows *Secure Enclave* and that
   signing prompts for Touch ID.

Keys created by a free build (CryptoKit blobs) keep working after switching to
signed builds; new pairings then use the keychain.

The Electron fuses from plan §7.1 are set in [electron-builder.yml](electron-builder.yml).
Updates: the agent reads the latest release (version, date, notes) from the
GitHub Releases API, and installs from that release's `latest*.yml` feed.
**Check for updates** is in the agent window and the tray menu. Free macOS
builds and `npm run dev` open the release page instead of installing.
