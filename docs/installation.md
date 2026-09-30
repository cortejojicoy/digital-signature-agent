# Installing Kukux Sign Agent

The agent is a small menu-bar (macOS) or notification-area (Windows) app. It
keeps a signing key in this computer's security chip, so the web app can
show that a signature was made on *this* machine, approved with Touch ID or
Windows Hello.

You need to install it once per computer. Nothing else needs to be set up:
the installer registers the `kukuxsign://` links that the web app uses.

| | macOS | Windows |
|---|---|---|
| Supported | macOS 12 or newer, Apple silicon or Intel | Windows 10 22H2 or Windows 11, 64-bit |
| Admin rights | Not needed (installs to `~/Applications` if `/Applications` isn't writable) | Not needed (per-user install) |
| Best protection | Mac with Touch ID or a T2 / Apple silicon chip | A TPM 2.0 with Windows Hello set up |

## Quick install

### macOS

Open **Terminal** and run:

```sh
curl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash
```

### Windows

Open **PowerShell** (not as administrator) and run:

```powershell
irm https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.ps1 | iex
```

The agent starts once it's installed. Next, pair it:

1. In the web app, open **My signing devices** and choose **Pair desktop agent**.
2. Enter the address and code it shows in the agent. If the web app shows a
   pairing link, click it and the agent fills both in for you.
3. Approve the Touch ID or Windows Hello prompt.
4. Back in the browser, confirm **Pair this computer**.

From then on, **Sign with this computer** appears when you sign a document.

## What the installer checks

The scripts refuse to install anything that fails these checks:

1. **Integrity.** The download's SHA-512 must match `latest-mac.yml` or
   `latest.yml` from the same release. These are the files the agent's
   auto-updater uses.
2. **Authenticity.**
   - macOS: the app must pass `codesign --verify --strict`, pass Gatekeeper
     (`spctl`, which requires a Developer ID signature and notarization), have
     the bundle id `com.kukux.signagent`, and be signed by the release's Apple
     team id.
   - Windows: the installer's Authenticode signature must be `Valid` and come
     from the expected publisher.
3. **Transport.** Downloads use HTTPS only. Plain HTTP is allowed only for
   `localhost` and `127.0.0.1` when testing a local release directory.

The macOS script runs everything inside one function, so a download that
gets cut off halfway runs nothing. You can read both scripts before running
them:
[install.sh](../scripts/install.sh) · [install.ps1](../scripts/install.ps1).

## Options

Pass options after `bash -s --` on macOS. On Windows, use the script-block
form or environment variables.

```sh
# macOS: a specific version
curl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash -s -- --version 1.2.0
```

```powershell
# Windows: a specific version
& ([scriptblock]::Create((irm https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.ps1))) -Version 1.2.0
```

| macOS (`install.sh`) | Windows (`install.ps1`) | Environment variable | Meaning |
|---|---|---|---|
| `--version 1.2.0` | `-Version 1.2.0` | `KUKUX_AGENT_VERSION` | Install that version instead of the latest |
| `--base-url <url>` | `-BaseUrl <url>` | `KUKUX_AGENT_BASE_URL` | Download from a self-hosted release directory ([below](#self-hosting-the-downloads)) |
| `--from <file>` | `-From <file>` | | Install a `.zip`/`.dmg` or `.exe` you already downloaded |
| `--dir <path>` | | `KUKUX_AGENT_INSTALL_DIR` | Install location (macOS) |
| `--no-launch` | `-NoLaunch` | | Don't start the agent afterwards |
| `--allow-unsigned` | `-AllowUnsigned` | `KUKUX_AGENT_ALLOW_UNSIGNED=1` | Skip the signature checks. **Only for your own development builds.** |
| `--uninstall [--purge]` | `-Uninstall [-Purge]` | | Remove the agent (and, with purge, its settings) |
| | | `KUKUX_AGENT_TEAM_ID` / `KUKUX_AGENT_PUBLISHER` | Override the expected Apple team id / Windows publisher |

## Manual install (no terminal)

Download the file for your computer from the
[latest release](https://github.com/cortejojicoy/digital-signature-agent/releases/latest):

| Computer | File |
|---|---|
| Mac with Apple silicon (M1 and later) | `kukux-sign-agent-<version>-mac-arm64.dmg` |
| Intel Mac | `kukux-sign-agent-<version>-mac-x64.dmg` |
| Windows PC | `kukux-sign-agent-<version>-win-x64.exe` |

- **macOS:** open the `.dmg` and drag **Kukux Sign Agent** into
  **Applications**. Open it once from Applications. The key icon appears in the
  menu bar.
- **Windows:** run the `.exe`. It installs for your account only and starts
  the agent. The key icon appears in the notification area (it may be under
  the **^** arrow).

To get the same checks as the quick install, run the script on the file you
downloaded:

```sh
bash install.sh --from ~/Downloads/kukux-sign-agent-1.2.0-mac-arm64.dmg
```

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -From "$HOME\Downloads\kukux-sign-agent-1.2.0-win-x64.exe"
```

## Rolling out to many computers

Both installers work silently, with no prompts and no admin rights, so they
run as-is from an MDM or a login script.

| Tool | Command |
|---|---|
| Jamf / Kandji / Intune for Mac (script, run as the user) | `curl -fsSL <base>/install.sh \| bash -s -- --no-launch` |
| Intune / SCCM / GPO (user context) | `powershell -NoProfile -ExecutionPolicy Bypass -Command "irm <base>/install.ps1 \| iex"` |
| Intune Win32 app from the `.exe` | install `kukux-sign-agent-<version>-win-x64.exe /S`; uninstall `powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall` (it finds the install in the per-user uninstall registry) |

Each user still pairs their own computer, because pairing is what ties the
machine's key to *their* account.

## Self-hosting the downloads

Some deployments (for example, government networks without GitHub access) need
to serve the installers from their own server. Put these files from a release
in one directory served over HTTPS:

```
https://downloads.example.gov.ph/kukux-sign-agent/
├── install.sh
├── install.ps1
├── latest-mac.yml
├── latest.yml
├── kukux-sign-agent-1.2.0-mac-arm64.zip   (+ .dmg for manual installs)
├── kukux-sign-agent-1.2.0-mac-x64.zip     (+ .dmg)
└── kukux-sign-agent-1.2.0-win-x64.exe
```

Then install with `--base-url` / `-BaseUrl`:

```sh
curl -fsSL https://downloads.example.gov.ph/kukux-sign-agent/install.sh | bash -s -- --base-url https://downloads.example.gov.ph/kukux-sign-agent
```

```powershell
$env:KUKUX_AGENT_BASE_URL = 'https://downloads.example.gov.ph/kukux-sign-agent'; irm "$env:KUKUX_AGENT_BASE_URL/install.ps1" | iex
```

For auto-updates to come from the same place, build the agent with
`-c.publish.provider=generic -c.publish.url=https://downloads.example.gov.ph/kukux-sign-agent`.
Point `SIGNATURE_AGENT_DOWNLOAD_URL` in the Laravel app at this directory, so
the web app's *"Don't have the agent? Download"* link goes there too.

## Updating

The agent updates itself in the background. It checks at startup and every
six hours, and verifies each update's signature before installing it. If the
web app requires a newer version, the agent starts an update straight away.
Re-running the quick install also updates it.

## Uninstalling

First, unpair: open the agent and click **Unpair**, or revoke the computer in
the web app under **My signing devices**. Then:

```sh
curl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash -s -- --uninstall --purge
```

```powershell
& ([scriptblock]::Create((irm https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.ps1))) -Uninstall -Purge
```

`--purge` / `-Purge` also removes the paired-app list and settings. The signing
keys can't be copied off the chip and can't be used without the agent, so
none of them is ever usable on another machine.

## Troubleshooting

| Problem | Fix |
|---|---|
| macOS: *"Gatekeeper rejected the app"* | The download isn't a notarized release (for example, a local build). Use an official release, or pass `--allow-unsigned` only for a build you made yourself. |
| macOS: the status screen says *Software key · lower assurance* | The Mac has no Secure Enclave (an Intel Mac without a T2 chip, or a VM), or you're running an unsigned build. Signing still works, but the web app shows a lower assurance level and may refuse it if the organisation requires hardware keys. |
| Windows: *"signature is NotSigned / HashMismatch"* | The file was changed or isn't an official build. Download it again from the release page. |
| Windows: no Windows Hello prompt | Set up Windows Hello (Settings → Accounts → Sign-in options). Without it, the agent uses the TPM without an approval prompt, and servers that require presence refuse to pair. |
| Windows: *"running scripts is disabled on this system"* | Use the `irm … \| iex` one-liner (it doesn't run a script file), or `powershell -ExecutionPolicy Bypass -File .\install.ps1`. |
| Clicking **Sign with this computer** does nothing | Start the agent once (it registers the `kukuxsign://` link), then try again. On macOS, check that only one copy is installed (`/Applications` or `~/Applications`). |
| The web app says the agent is outdated | The agent updates itself within a minute. Re-running the quick install also works. |

## For developers: installing a local build

```sh
npm run dist:local              # unsigned .zip/.dmg + latest-mac.yml in release/
./scripts/install.sh --from release/kukux-sign-agent-*-mac-arm64.zip --allow-unsigned
```

Or test the full download path by serving `release/` locally:

```sh
cp scripts/install.sh release/ && (cd release && python3 -m http.server 8899)
curl -fsSL http://127.0.0.1:8899/install.sh | bash -s -- --base-url http://127.0.0.1:8899 --allow-unsigned
```

A local build is ad-hoc signed, so it can't use the Secure Enclave (see
[README](../README.md#release-builds)). It uses JIT-only entitlements,
because the restricted keychain entitlements make macOS kill an app at
launch unless it has a matching provisioning profile.
