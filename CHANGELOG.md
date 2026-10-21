# Changelog

Short and plain: what changed for people using the agent. The release
workflow copies a version's bullets into its GitHub release.

When tagging a release, rename `Unreleased` to the version, e.g.
`## 0.3.0 (2026-10-05)`.

## Unreleased

- Verify a PDF: open a signed PDF with Kukux Sign Agent (Open With), drop it on the window, or choose it. The agent checks the file's signature on this computer and asks your paired apps whether it's a copy they issued, and shows who has signed
- Only the file's fingerprint goes to your paired apps; the file itself stays on this computer
- With a software certificate, **Open in Kukux Sign Agent** pairs without an address or code: check the app and enter your certificate's password
- Your certificate's password approves pairing and every signing, in place of Touch ID / Windows Hello. After 5 wrong passwords the agent waits before the next try
- Switching key storage unpairs the apps that used the other storage and deletes their keys, after asking. The imported certificate stays unless you remove it too
- Certificates imported by earlier test builds need to be imported again
- Choose where your signing key lives: this computer's security chip (Secure Enclave / TPM), or a software certificate
- Import a .p12 or .pfx certificate, such as your PNPKI certificate: see its name, issuer and expiry before importing. Its key is locked to this computer and can't be exported (macOS 15 or later, Windows)
- Pair apps with your certificate: the app checks its issuer and that it hasn't been revoked
- The status window lists the apps paired with the key storage you chose
- Sign in to the UPLB Signature Hub from this computer: check the code your browser shows, then approve with Touch ID or Windows Hello
- The confirm window says which app asked, e.g. "performance asks: IPCR Q3"
- Approve moving your signature to a new computer
- Your name appears in the agent once you tell the hub who you are
- Pairing now points to **Pair this computer** on the website
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
