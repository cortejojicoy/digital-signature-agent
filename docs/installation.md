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

## Free and signed builds

The agent is free to build and distribute. Paid code signing is optional, and
it doesn't change how signing keys are protected.

| | Free build (default) | Signed build (optional, paid) |
|---|---|---|
| Cost | Nothing | Apple Developer Program (US$99/year) and/or a Windows code-signing certificate |
| Where signing keys live | Secure Enclave (Mac) / TPM + Windows Hello (PC) | Same |
| Touch ID / Windows Hello on every signature | Yes, enforced by the chip | Same |
| One-line install | Works, no extra steps | Works |
| Double-clicking a downloaded `.dmg` / `.exe` | Asks once: macOS → System Settings → Privacy & Security → **Open Anyway**; Windows → SmartScreen → **More info → Run anyway** | Opens without warnings |
| Updates | Windows: automatic. macOS: the agent tells you, and you re-run the installer | Automatic on both |

What paid signing buys is the operating system's trust in *who published the
app*: Apple or a certificate authority verifies your identity and, on macOS,
scans each build (notarization). It isn't needed for the hardware keys:
- **On macOS**, free builds keep keys in the Secure Enclave through CryptoKit,
  outside the keychain. Only an encrypted blob that this Mac's chip alone can
  use is stored on disk.
- **On Windows**, the TPM and Windows Hello work the same whether or not the
  app is signed.

The release workflow publishes a free build whenever a platform's signing
secrets aren't set (see [.github/workflows/release.yml](../.github/workflows/release.yml)).
The release notes say which kind each release is.

## What the installer checks

The scripts refuse to install anything that fails these checks:

1. **Integrity.** The download's SHA-512 must match `latest-mac.yml` or
   `latest.yml` from the same release. These are the files the agent's
   auto-updater uses.
2. **The right app, undamaged.** macOS: the bundle id must be
   `com.kukux.signagent`, and the app's code signature must be intact
   (`codesign --verify --strict`; for free builds this is an ad-hoc
   signature). Windows: a signed installer whose signature is broken is
   always refused.
3. **Publisher (signed releases only).** macOS: Gatekeeper must accept the app
   (`spctl`: a Developer ID signature and notarization), signed by the release's
   Apple team id. Windows: the Authenticode signature must be `Valid` and come
   from the expected publisher. Each release's scripts know whether it was
   signed, so a signed release can't be swapped for an unsigned copy.
4. **Transport.** Downloads use HTTPS only. Plain HTTP is allowed only for
   `localhost` and `127.0.0.1` when testing a local release directory.

For a free build, after these checks the installer removes the
"downloaded from the internet" mark, so macOS and Windows open the agent
without a Gatekeeper or SmartScreen prompt.

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
| `--allow-unsigned` | `-AllowUnsigned` | `KUKUX_AGENT_ALLOW_UNSIGNED=1` | Skip the code-signature checks entirely (the SHA-512 check still runs). Not needed for free releases, **only for your own development builds.** |
| `--uninstall [--purge]` | `-Uninstall [-Purge]` | | Remove the agent (and, with purge, its settings) |
| | | `KUKUX_AGENT_TEAM_ID` / `KUKUX_AGENT_PUBLISHER` | Override the expected Apple team id / Windows publisher |
| | | `KUKUX_AGENT_RELEASE_SIGNED=true\|false` | Override whether the release is expected to be signed |

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
  menu bar. For a free build, macOS first says it *"can't verify"* the app.
  Click **Done**, then open **System Settings → Privacy & Security** and click
  **Open Anyway** next to Kukux Sign Agent. You only need to do this once per
  version.
- **Windows:** run the `.exe`. It installs for your account only and starts
  the agent. The key icon appears in the notification area (it may be under
  the **^** arrow). For a free build, SmartScreen shows *"Windows protected your
  PC"*. Click **More info → Run anyway**.

To get the same checks as the quick install, and to skip those prompts, run
the script on the file you downloaded:

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

The agent checks for updates at startup and every six hours. If the web app
requires a newer version, it checks straight away.

- **Signed builds** update themselves in the background, and verify each
  update's signature before installing it.
- **Free builds on Windows** update themselves too, and verify each update
  against the SHA-512 in `latest.yml` over HTTPS.
- **Free builds on macOS** can't replace themselves (macOS only lets signed
  apps do that). The agent shows a notification; click it and re-run the
  one-line installer. Your pairings and keys are kept.

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
| macOS: *"Gatekeeper rejected the app: this release should be signed…"* | The release is marked as signed, but the file isn't. The download was replaced or damaged. Download it again from the release page. |
| macOS: *"can't verify"* / *"Apple could not verify"* when opening | A free build opened from a browser download. Use System Settings → Privacy & Security → **Open Anyway**, or install with the one-line installer. |
| macOS: the status screen says *Software key · lower assurance* | The Mac has no Secure Enclave (an Intel Mac without a T2 chip, or a VM). Signing still works, but the web app shows a lower assurance level and may refuse it if the organisation requires hardware keys. |
| macOS (free build, Mac without a Secure Enclave): a keychain password prompt after an update | Expected on these Macs: the software key lives in the keychain, whose access is tied to the app's signature. Click **Always Allow**. |
| Windows: *"Windows protected your PC"* | A free build started from a browser download. Click **More info → Run anyway**, or install with the one-line installer. |
| Windows: *"signature is NotSigned / HashMismatch"* | The file was changed or isn't an official build. Download it again from the release page. |
| Windows: no Windows Hello prompt | Set up Windows Hello (Settings → Accounts → Sign-in options). Without it, the agent uses the TPM without an approval prompt, and servers that require presence refuse to pair. |
| Windows: *"running scripts is disabled on this system"* | Use the `irm … \| iex` one-liner (it doesn't run a script file), or `powershell -ExecutionPolicy Bypass -File .\install.ps1`. |
| Clicking **Sign with this computer** does nothing | Start the agent once (it registers the `kukuxsign://` link), then try again. On macOS, check that only one copy is installed (`/Applications` or `~/Applications`). |
| The web app says the agent is outdated | The agent updates itself within a minute. Re-running the quick install also works. |

## For developers: installing a local build

```sh
npm run dist:local              # free .zip/.dmg + latest-mac.yml in release/
./scripts/install.sh --from release/kukux-sign-agent-*-mac-arm64.zip
```

Or test the full download path by serving `release/` locally:

```sh
cp scripts/install.sh release/ && (cd release && python3 -m http.server 8899)
curl -fsSL http://127.0.0.1:8899/install.sh | bash -s -- --base-url http://127.0.0.1:8899
```

A local build is the same as a free release: ad-hoc signed, with keys in the
Secure Enclave via CryptoKit. It uses JIT-only entitlements, because the
restricted keychain entitlements make macOS kill an app at launch unless it has
a matching provisioning profile.
