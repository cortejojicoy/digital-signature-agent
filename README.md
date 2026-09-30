# Kukux Sign Agent

A desktop signing agent for [`kukux/digital-signature`](../digital-signature).
It creates signing keys inside the machine's security chip (the Secure
Enclave on macOS, the TPM with Windows Hello on Windows), pairs them with the
web app, and proves on each signing that *this* machine was used, with Touch
ID or Windows Hello enforced by the key itself.

Design: [desktop-agent-plan.md](desktop-agent-plan.md). Wire contract for the
server: [docs/protocol.md](docs/protocol.md).

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
the current user, register `kukuxsign://`, and start the agent. For manual
installs, MDM rollout, self-hosted downloads and uninstalling, see
[docs/installation.md](docs/installation.md).

## Status

| Phase (plan §13) | State |
|---|---|
| 0: spikes | **Open.** 0a (Secure Enclave from a signed, notarized build) and 0b (Hello prompt parenting) need real signing identities and hardware. |
| 1: native module | Done. macOS is built and tested; Windows is written but not yet compiled (needs a Windows runner). |
| 2: Electron shell | Done. Pairs with and signs against the local mock server. |
| 3–4: package | Not in this repo. Implement [docs/protocol.md](docs/protocol.md) in `kukux/digital-signature`. |
| 5: distribution | Release workflow, install scripts, fuses, entitlements and updater are in place. It needs certificates. The unsigned local package and `install.sh` are tested on macOS. |

An unsigned development build **cannot** use the Secure Enclave. macOS
refuses the data-protection keychain without the `keychain-access-groups`
entitlement (`errSecMissingEntitlement`, -34018). The agent then falls back to
a non-exportable software key in the login keychain and reports it honestly:
*Software key · lower assurance*, with no OS approval prompt.

## Layout

```
native/                  keystore.node (N-API, C++ / Objective-C++)
  include/keystore.h     platform-neutral interface (§4.1)
  src/addon.cc           async N-API binding (§4.2)
  src/common/            SPKI wrapping, raw→DER ECDSA, salted hardware hash
  src/mac/               Secure Enclave / keychain, device info (§5)
  src/win/               Windows Hello, TPM + software CNG, device info (§6)
  test/                  native tests (node --test)
src/main/                Electron main process
  agent.ts               composes everything below
  keystore.ts            typed addon wrapper
  canonical.ts           proof messages (shared vectors with PHP)
  protocol.ts            kukuxsign:// link parsing
  api.ts                 HTTPS client: pinned origin, bearer + X-Agent-Proof
  pairing.ts, jobs.ts    §8.1 and §8.3 flows
  store.ts               servers.json + safeStorage-encrypted tokens
  index.ts, updater.ts   lifecycle, tray, windows, hardening, IPC
src/preload/             contextBridge API (no generic sign)
src/renderer/            React UI: status, pairing, confirm
test/                    vitest: unit + end-to-end against test/support/mock-server.ts
```

## Development

Requirements: Node ≥ 22.18. On macOS, Xcode Command Line Tools. On Windows,
Visual Studio 2022 with the C++ workload and Windows 10/11 SDK (C++/WinRT
headers).

```sh
npm install
npm run build:native        # native/build/Release/keystore.node
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
open the returned `kukuxsign://job/…` link. Plain `http://localhost` origins
are accepted only in unpackaged builds.

> Running inside VS Code's terminal? It may export `ELECTRON_RUN_AS_NODE=1`,
> which makes Electron start as plain Node. Use `env -u ELECTRON_RUN_AS_NODE npm run dev`.

Environment switches:

| Variable | Effect |
|---|---|
| `KUKUX_KEYSTORE_BACKEND=software` | Force software keys (CI) |
| `KUKUX_KEYSTORE_DEBUG=1` | Log why hardware key creation fell back (macOS) |
| `KUKUX_BIOMETRY_ONLY=1` | macOS: require biometrics (`BiometryCurrentSet`) instead of biometrics-or-password |

## Release builds

Push a `v<version>` tag. [.github/workflows/release.yml](.github/workflows/release.yml)
builds, signs and notarizes both platforms, publishes the installers and
`latest*.yml` to GitHub Releases, pins the expected Apple team id and Windows
publisher into `install.sh` / `install.ps1`, and attaches them to the release.
It needs these secrets in a `release` environment: `MAC_CSC_LINK`,
`MAC_CSC_KEY_PASSWORD`, `MAC_PROVISIONING_PROFILE_B64`, `APPLE_ID`,
`APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`, `WIN_CSC_LINK`, and
`WIN_CSC_KEY_PASSWORD`. Set the `WIN_PUBLISHER_NAME` variable too.

Locally:

```sh
npm run dist:mac            # needs Developer ID + provisioning profile + notarization credentials
npm run dist:win            # needs an Authenticode signing setup
npm run dist:local          # unsigned build for testing the package and install scripts
```

On macOS, `rebuild:native` produces a universal (arm64 + x86_64)
`keystore.node`, so the arm64 and x64 packages both load it.

Before the first macOS release (spike 0a):

1. Register the App ID `com.kukux.signagent` with a keychain access group.
2. Create a **Developer ID** provisioning profile for it and save it as
   `build/embedded.provisionprofile`.
3. Replace `TEAMID` in [build/entitlements.mac.plist](build/entitlements.mac.plist).
4. Build, notarize, and check on real hardware that the status view shows
   *Secure Enclave* and that signing prompts for Touch ID.

If step 4 fails, a fallback worth evaluating is CryptoKit's
`SecureEnclave.P256` keys persisted as their `dataRepresentation` (an
SE-wrapped blob that is useless off this device), which needs no keychain
entitlement. It would add a small Swift shim.

The Electron fuses from plan §7.1 are set in [electron-builder.yml](electron-builder.yml).
Updates are served from `SIGNATURE_AGENT_UPDATE_URL`.
