# Changelog

Short and plain: what changed for people using the agent. The release
workflow copies a version's bullets into its GitHub release.

When tagging a release, rename `Unreleased` to the version, e.g.
`## 0.3.0 (2026-10-05)`.

## Unreleased

- Answers an app's "is this your paired computer?" check silently, so apps that require it can let you sign from this computer
- Pair one computer with several apps, one signature per app
- Re-pairing the same account now updates your device instead of adding a new one
- See your other paired devices for each app
- Knows what your computer is, from MacBook Air to all-in-one PC
- Virtual machines can't pair by default
- Unpairing offline now finishes once you're back online
- One computer per account for each app: pairing a second computer tells you which one to remove first
- Re-pairing works on computers without a hardware id, and after a logic-board swap
- PCs that share a placeholder firmware id are no longer mistaken for one computer
- Unpairing while the app can't be reached now asks before removing your signature
- The status window lists unpairs the app hasn't heard about yet, with Retry now
- Windows fit their content instead of a fixed size
- Click the version to see what the agent does and update it
- Free Mac builds now update themselves instead of opening the download page
- The installer shows each step: what it downloads, checks and installs

## 0.2.2 (2026-10-01)

- Release builds now get their version from the tag

## 0.2.1 (2026-10-01)

- Smaller update button next to the version number

## 0.2.0 (2026-10-01)

- Check for updates and see what's new before installing
- Developer mode: pair with test apps on your network over HTTP
- Icon buttons with labels on hover

## 0.1.0 (2026-09-30)

- First release: pair with an app and approve signings with Touch ID or Windows Hello
- Your signing key stays in the Secure Enclave or TPM
