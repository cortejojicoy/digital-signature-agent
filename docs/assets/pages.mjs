// Guide pages for the docs site. Keep them short: one task per section, a
// code block where it saves words. The API reference lives in reference.mjs.
import { editor, httpCall, plain, terminal, urlBar } from './code.mjs';

const r = String.raw;
const RELEASES = 'https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download';

const note = (html, kind = 'note') => `<div class="callout callout-${kind}">${html}</div>`;
const steps = (items) => `<ol class="steps">${items.map((i) => `<li>${i}</li>`).join('')}</ol>`;
const table = (head, rows) =>
  `<div class="table-wrap"><table><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows
    .map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join('')}</tr>`)
    .join('')}</tbody></table></div>`;
const cards = (items) =>
  `<div class="card-grid">${items
    .map(([href, title, text]) => `<a class="card" href="${href}"><strong>${title}</strong><span>${text}</span><span class="card-arrow" aria-hidden="true">→</span></a>`)
    .join('')}</div>`;

export const groups = ['Start here', 'Guides', 'Contributing', 'API'];

export const pages = [
  // ─────────────────────────────── Start here ───────────────────────────────
  {
    id: 'introduction',
    group: 'Start here',
    title: 'Introduction',
    description: 'What the agent does and how a signature is made.',
    body: () => `
<p class="lede">Kukux Sign Agent is a small desktop app for <code>kukux/digital-signature</code>. It keeps your signing key in the
computer's security chip and proves which machine signed, approved with Touch ID or Windows Hello.</p>

<div class="features">
  <div class="feature"><span class="feature-icon">🔐</span><strong>Hardware keys</strong><span>Secure Enclave on Mac, TPM on Windows. Keys can't be copied off.</span></div>
  <div class="feature"><span class="feature-icon">👆</span><strong>OS approval</strong><span>The key itself requires Touch ID or Windows Hello on every signature.</span></div>
  <div class="feature"><span class="feature-icon">🔗</span><strong>Pair once</strong><span>Enter a code from the web app. No extensions, no local servers.</span></div>
  <div class="feature"><span class="feature-icon">✍️</span><strong>Signed requests</strong><span>Every API call is signed, so a leaked token alone is useless.</span></div>
</div>

<h2 id="how-signing-works">How signing works</h2>
${steps([
  '<strong>Pair.</strong> Enter the code from <em>My signing devices</em>. The agent creates two keys and registers them.',
  '<strong>Start signing in the browser.</strong> The web app opens a <code>kukuxsign://</code> link.',
  '<strong>Confirm.</strong> The agent shows the document. Click Approve, then pass Touch ID or Windows Hello.',
  '<strong>Done.</strong> The server verifies the proof and records <em>"Used on: MacBook Pro (Secure Enclave)"</em>.',
])}

<h2 id="next">Where to go next</h2>
${cards([
  ['#/installation', 'Install', 'One command on macOS or Windows.'],
  ['#/using-the-agent', 'Use it', 'Pair, sign, update and unpair.'],
  ['#/development', 'Contribute', 'Set up the repo and run the tests.'],
  ['#/how-the-api-works', 'API', 'How the agent talks to your server.'],
])}`,
  },
  {
    id: 'installation',
    group: 'Start here',
    title: 'Installation',
    description: 'Install on macOS or Windows, manually or with one command.',
    body: () => `
<p class="lede">Install once per computer. No admin rights needed.</p>
${table(
  ['', 'macOS', 'Windows'],
  [
    ['Supported', 'macOS 12+, Apple silicon or Intel', 'Windows 10 22H2 or 11, 64-bit'],
    ['Best protection', 'Touch ID, T2 or Apple silicon', 'TPM 2.0 with Windows Hello'],
    ['Installs to', '<code>/Applications</code> or <code>~/Applications</code>', 'Your user account'],
  ],
)}

<h2 id="macos">macOS</h2>
<p>Open <strong>Terminal</strong> and run:</p>
${terminal(`curl -fsSL ${RELEASES}/install.sh | bash`)}

<h2 id="windows">Windows</h2>
<p>Open <strong>PowerShell</strong> (not as administrator) and run:</p>
${terminal(`irm ${RELEASES}/install.ps1 | iex`, { os: 'win' })}
<p>The agent starts when it's done. Next: <a href="#/using-the-agent/pair">pair it</a>.</p>

<h2 id="what-gets-checked">What the installer checks</h2>
<ul>
  <li><strong>Integrity:</strong> SHA-512 must match the release's <code>latest*.yml</code>.</li>
  <li><strong>Identity:</strong> the right app, with an intact signature.</li>
  <li><strong>Publisher:</strong> signed releases must come from the expected Apple team or Windows publisher.</li>
  <li><strong>Transport:</strong> HTTPS only.</li>
</ul>

<h2 id="manual">Manual install</h2>
<p>Download from the <a href="https://github.com/cortejojicoy/digital-signature-agent/releases/latest">latest release</a>:</p>
${table(
  ['Computer', 'File'],
  [
    ['Mac, Apple silicon', '<code>kukux-sign-agent-&lt;version&gt;-mac-arm64.dmg</code>'],
    ['Mac, Intel', '<code>kukux-sign-agent-&lt;version&gt;-mac-x64.dmg</code>'],
    ['Windows', '<code>kukux-sign-agent-&lt;version&gt;-win-x64.exe</code>'],
  ],
)}
${note('Free builds ask once: macOS → <strong>System Settings → Privacy &amp; Security → Open Anyway</strong>. Windows → <strong>More info → Run anyway</strong>. The one-line installer skips this.')}

<h2 id="options">Options</h2>
${terminal(`# A specific version\ncurl -fsSL ${RELEASES}/install.sh | bash -s -- --version 1.2.0`)}
${terminal(`& ([scriptblock]::Create((irm ${RELEASES}/install.ps1))) -Version 1.2.0`, { os: 'win' })}
${table(
  ['macOS', 'Windows', 'Does'],
  [
    ['<code>--version 1.2.0</code>', '<code>-Version 1.2.0</code>', 'Install that version'],
    ['<code>--base-url &lt;url&gt;</code>', '<code>-BaseUrl &lt;url&gt;</code>', 'Download from your own server'],
    ['<code>--from &lt;file&gt;</code>', '<code>-From &lt;file&gt;</code>', 'Install a file you downloaded'],
    ['<code>--no-launch</code>', '<code>-NoLaunch</code>', "Don't start the agent"],
    ['<code>--uninstall [--purge]</code>', '<code>-Uninstall [-Purge]</code>', 'Remove it (and its settings)'],
  ],
)}

<h2 id="free-and-signed">Free and signed builds</h2>
<p>Paid code signing is optional. Keys are protected the same way either way.</p>
${table(
  ['', 'Free (default)', 'Signed'],
  [
    ['Keys in Secure Enclave / TPM', 'Yes', 'Yes'],
    ['Touch ID / Hello on every signature', 'Yes', 'Yes'],
    ['Opening a downloaded file', 'Asks once', 'No warning'],
    ['Updates', 'Windows: automatic. macOS: re-run the installer', 'Automatic'],
  ],
)}

<h2 id="uninstall">Uninstall</h2>
<p>Unpair first (in the agent, or in the web app under <strong>My signing devices</strong>), then:</p>
${terminal(`curl -fsSL ${RELEASES}/install.sh | bash -s -- --uninstall --purge`)}
${terminal(`& ([scriptblock]::Create((irm ${RELEASES}/install.ps1))) -Uninstall -Purge`, { os: 'win' })}`,
  },
  {
    id: 'using-the-agent',
    group: 'Start here',
    title: 'Using the agent',
    description: 'Pair with an app, sign, update and unpair.',
    body: () => `
<p class="lede">The agent lives in the menu bar (macOS) or notification area (Windows).</p>

<h2 id="pair">Pair</h2>
${steps([
  'In the web app, open <strong>My signing devices → Pair desktop agent</strong>.',
  'In the agent, click <strong>+</strong> and enter the address and code. A pairing link fills both in.',
  'Approve the Touch ID or Windows Hello prompt.',
  'Back in the browser, confirm <strong>Pair this computer</strong>.',
])}
${urlBar('kukuxsign://pair?o=https%3A%2F%2Fsign.example.gov.ph&c=K7QM-2XPD', 'A pair link only fills the form. You still check the address and click Pair.')}

<h2 id="sign">Sign</h2>
${steps([
  'In the web app, choose <strong>Sign with this computer</strong>.',
  'The agent shows the app, document and signer. Approve only if you just started it.',
  'Pass Touch ID or Windows Hello. The browser continues on its own.',
])}

<h2 id="updates">Updates</h2>
<p>The update icon sits next to the version number. It checks GitHub, then turns into <strong>Download</strong> or
<strong>Restart to update</strong>. The agent also checks at startup and every six hours. Click the version itself
for a short summary of what the agent does, and an <strong>Update</strong> button when there's a new version.</p>
${table(
  ['Build', 'Update'],
  [
    ['Signed, or Windows', 'Downloads, then installs on restart'],
    ['Free macOS', 'Downloads the .zip, checks its SHA-512 and signature like the installer, then swaps the app on restart'],
    ['<code>npm run dev</code>', 'Opens the release page'],
  ],
)}

<h2 id="unpair">Unpair</h2>
<p>Click the unlink icon next to the app. The keys are deleted and the server revokes the device.</p>

<h2 id="developer-mode">Developer mode</h2>
<p>Lets the agent pair with apps on your computer or local network over plain HTTP. Off by default; always on under
<code>npm run dev</code>. See <a href="#/local-testing">Local testing</a>.</p>`,
  },

  // ──────────────────────────────── Guides ─────────────────────────────────
  {
    id: 'local-testing',
    group: 'Guides',
    title: 'Local testing',
    description: 'Pair with a Laravel app on localhost or your LAN.',
    body: () => `
<p class="lede">Turn on <strong>Developer mode</strong> in the agent, then pair with your local app.</p>
${table(
  ['Allowed over HTTP', 'Examples'],
  [
    ['Loopback', '<code>localhost</code>, <code>127.0.0.1</code>, <code>[::1]</code>'],
    ['Private network', '<code>10.x</code>, <code>172.16–31.x</code>, <code>192.168.x</code>'],
    ['Local names', '<code>*.local</code>, <code>*.test</code>, <code>*.localhost</code>'],
  ],
)}
<p>Public addresses stay HTTPS-only. Developer mode also trusts your OS certificates, so Herd, Valet and mkcert HTTPS work.</p>

<h2 id="same-machine">Same machine</h2>
${terminal(`php artisan serve\n> Server running on [http://127.0.0.1:8000]`)}
${editor('.env', 'yaml', 'APP_URL=http://127.0.0.1:8000')}

<h2 id="same-network">Another machine on the network</h2>
${terminal(`php artisan serve --host=0.0.0.0 --port=8000`)}
${editor('.env', 'yaml', 'APP_URL=http://192.168.1.20:8000')}
<p>Open the web app at that same address on the agent's machine. Allow port 8000 through the server's firewall.</p>

<h2 id="mock-server">Without Laravel</h2>
${terminal(`npm run mock-server -- --lan\n> Mock signing server on http://192.168.1.20:8787`)}

<h2 id="checklist">Checklist</h2>
<ul>
  <li>The address must match <code>APP_URL</code> exactly. <code>localhost</code> ≠ <code>127.0.0.1</code>.</li>
  <li>Clocks must be within 60 seconds.</li>
  <li>macOS 15+: allow Local Network access when asked.</li>
</ul>
${note('Plain HTTP is unencrypted on the network. Use it for testing only.', 'warn')}`,
  },
  {
    id: 'rollout',
    group: 'Guides',
    title: 'Rollout & self-hosting',
    description: 'Deploy to many computers, or serve the installers yourself.',
    body: () => `
<p class="lede">Both installers run silently without admin rights, so MDM tools can run them as-is.</p>

<h2 id="mdm">MDM</h2>
${table(
  ['Tool', 'Command'],
  [
    ['Jamf, Kandji, Intune for Mac (as the user)', '<code>curl -fsSL &lt;base&gt;/install.sh | bash -s -- --no-launch</code>'],
    ['Intune, SCCM, GPO (user context)', '<code>powershell -NoProfile -ExecutionPolicy Bypass -Command "irm &lt;base&gt;/install.ps1 | iex"</code>'],
    ['Intune Win32 app', '<code>kukux-sign-agent-&lt;version&gt;-win-x64.exe /S</code>'],
  ],
)}
<p>Each user still pairs their own computer.</p>

<h2 id="self-hosting">Self-hosting</h2>
<p>Serve these files from one HTTPS directory:</p>
${plain(`https://downloads.example.gov.ph/kukux-sign-agent/
├── install.sh
├── install.ps1
├── latest-mac.yml
├── latest.yml
├── kukux-sign-agent-1.2.0-mac-arm64.zip
├── kukux-sign-agent-1.2.0-mac-x64.zip
└── kukux-sign-agent-1.2.0-win-x64.exe`)}
${terminal(`curl -fsSL https://downloads.example.gov.ph/kukux-sign-agent/install.sh | bash -s -- \\\n  --base-url https://downloads.example.gov.ph/kukux-sign-agent`)}
${terminal(r`$env:KUKUX_AGENT_BASE_URL = 'https://downloads.example.gov.ph/kukux-sign-agent'; irm "$env:KUKUX_AGENT_BASE_URL/install.ps1" | iex`, { os: 'win' })}
<p>For updates from the same place, build with
<code>-c.publish.provider=generic -c.publish.url=&lt;directory&gt;</code>, and set <code>SIGNATURE_AGENT_DOWNLOAD_URL</code> in the
Laravel app.</p>`,
  },
  {
    id: 'troubleshooting',
    group: 'Guides',
    title: 'Troubleshooting',
    description: 'Common problems and fixes.',
    body: () =>
      table(
        ['Problem', 'Fix'],
        [
          ['macOS: <em>"can\'t verify"</em> when opening', '<strong>System Settings → Privacy &amp; Security → Open Anyway</strong>, or use the one-line installer.'],
          ['Windows: <em>"Windows protected your PC"</em>', '<strong>More info → Run anyway</strong>, or use the one-line installer.'],
          ['<em>Software · lower assurance</em>', 'No Secure Enclave or TPM (older Intel Mac, VM). Signing works at a lower level.'],
          ['No Windows Hello prompt', 'Set up Hello in <strong>Settings → Accounts → Sign-in options</strong>.'],
          ['"Running scripts is disabled"', 'Use the <code>irm … | iex</code> one-liner.'],
          ['<em>Sign with this computer</em> does nothing', 'Start the agent once so it registers <code>kukuxsign://</code> links.'],
          ['"Agent outdated"', 'The agent updates itself within a minute, or re-run the installer.'],
          ['<code>origin_mismatch</code>', 'Use the exact address from <code>APP_URL</code>.'],
          ['"Check this computer\'s clock"', 'Sync the clock; requests allow ±60 s.'],
          ['"Gatekeeper rejected the app"', 'The download was replaced or damaged. Download it again.'],
        ],
      ),
  },

  // ────────────────────────────── Contributing ─────────────────────────────
  {
    id: 'development',
    group: 'Contributing',
    title: 'Development setup',
    description: 'Clone, build and run the agent locally.',
    body: () => `
<h2 id="requirements">Requirements</h2>
<ul>
  <li>Node 22.18 or newer</li>
  <li>macOS: Xcode Command Line Tools (clang, swiftc)</li>
  <li>Windows: Visual Studio 2022 with the C++ workload and the Windows SDK</li>
</ul>

<h2 id="setup">Set up</h2>
${terminal(`git clone https://github.com/cortejojicoy/digital-signature-agent.git
cd digital-signature-agent
npm install
npm run build:native`)}

<h2 id="run">Run</h2>
${terminal(`npm run mock-server    # a local test server: prints an address and a code
npm run dev            # builds and starts the agent`)}
${note('In VS Code\'s terminal, <code>ELECTRON_RUN_AS_NODE</code> may be set. Use <code>env -u ELECTRON_RUN_AS_NODE npm run dev</code>.')}

<h2 id="layout">Project layout</h2>
${plain(`src/
  main/       Electron main process: agent, API client, pairing, jobs, updater
  preload/    the window.agent bridge
  renderer/   React UI (status, pair, confirm)
  shared/     IPC types
native/       keystore.node: Secure Enclave (Obj-C++/Swift), TPM + Hello (C++)
test/         vitest + mock server
scripts/      build, install.sh, install.ps1
docs/         this site`)}

<h2 id="environment">Environment switches</h2>
${table(
  ['Variable', 'Effect'],
  [
    ['<code>KUKUX_KEYSTORE_BACKEND=software</code>', 'Use software keys (CI, VMs)'],
    ['<code>KUKUX_BIOMETRY_ONLY=1</code>', 'macOS: biometrics only, no password fallback'],
  ],
)}`,
  },
  {
    id: 'architecture',
    group: 'Contributing',
    title: 'Architecture',
    description: 'Processes, keys and the rules that keep them safe.',
    body: () => `
<div class="diagram" role="img" aria-label="Browser and server talk over HTTPS; the browser opens a kukuxsign link that wakes the agent; the agent talks to the server and to the native key store.">
  <div class="dg-row">
    <div class="dg-box"><strong>Browser</strong><span>Filament app</span></div>
    <div class="dg-arrow">HTTPS ⇄</div>
    <div class="dg-box"><strong>Server</strong><span>kukux/digital-signature</span></div>
  </div>
  <div class="dg-row dg-row-down">
    <div class="dg-arrow dg-v">kukuxsign:// ↓</div>
    <div class="dg-arrow dg-v">↑ signed HTTPS</div>
  </div>
  <div class="dg-agent">
    <strong>Desktop agent (Electron)</strong>
    <div class="dg-row">
      <div class="dg-box"><strong>Main</strong><span>TypeScript · API client, jobs, updater</span></div>
      <div class="dg-box"><strong>Renderer</strong><span>React · sandboxed UI</span></div>
      <div class="dg-box dg-chip"><strong>keystore.node</strong><span>Secure Enclave · TPM</span></div>
    </div>
  </div>
</div>

<h2 id="rules">Design rules</h2>
<ul>
  <li><strong>The browser never talks to the agent.</strong> A link wakes it; everything else goes through the server.</li>
  <li><strong>Links are never trusted.</strong> They carry only ids. The agent fetches the job from the paired origin.</li>
  <li><strong>Keys stay native.</strong> JavaScript holds key ids and gets signatures back, never key material.</li>
  <li><strong>The OS enforces approval.</strong> The confirm window is UX; Touch ID or Hello is the security boundary.</li>
</ul>

<h2 id="keys">Two keys per paired app</h2>
${table(
  ['Key', 'Prompt', 'Signs'],
  [
    ['Identity', 'Touch ID / Hello', 'Pairing proof and every signature'],
    ['Session', 'None', 'Each API request (<code>X-Agent-Proof</code>)'],
  ],
)}

<h2 id="hardening">Electron hardening</h2>
<ul>
  <li>Renderer: <code>sandbox</code>, <code>contextIsolation</code>, no Node, strict CSP, served from <code>app://</code>.</li>
  <li>The preload exposes a narrow API. There is no generic <code>sign(bytes)</code>.</li>
  <li>Fuses: no <code>RunAsNode</code>, ASAR integrity, app only from ASAR.</li>
</ul>`,
  },
  {
    id: 'testing',
    group: 'Contributing',
    title: 'Testing',
    description: 'Unit, end-to-end and native tests.',
    body: () => `
${terminal(`npm test               # vitest: proofs, links, API, store, end-to-end
npm run typecheck
npm run test:native    # native addon with the software backend
npm run test:all       # all of the above`)}

<h2 id="end-to-end">End-to-end</h2>
<p><code>test/agent.test.ts</code> drives the real agent against <code>test/support/mock-server.ts</code>, an in-memory server
that makes every check a real server must make.</p>

<h2 id="vectors">Shared test vectors</h2>
<p><code>test/fixtures/canonical-vectors.json</code> is used by the agent and the Laravel package, so both build identical proof messages.</p>

<h2 id="hardware">Before a release</h2>
${table(
  ['Machine', 'Expect'],
  [
    ['Apple silicon MacBook', 'Secure Enclave, Touch ID'],
    ['Mac mini / iMac', 'Secure Enclave, password prompt'],
    ['Windows 11, TPM + Hello', 'TPM, Hello prompt, attested'],
    ['VM without TPM', 'Software key'],
  ],
)}`,
  },
  {
    id: 'releasing',
    group: 'Contributing',
    title: 'Releasing',
    description: 'Tag a version; CI builds and publishes it.',
    body: () => `
<p class="lede">Push a version tag. The version comes from the tag; <code>package.json</code> doesn't need a bump.</p>
${terminal(`git tag v1.2.0\ngit push origin v1.2.0`)}
${editor('.github/workflows/release.yml', 'yaml', `- name: Stamp the tag's version into package.json
  run: npm version "\${{ needs.prepare.outputs.version }}" --no-git-tag-version --allow-same-version`)}

<h2 id="what-it-builds">What it builds</h2>
<ul>
  <li>macOS <code>.dmg</code> / <code>.zip</code> (arm64, x64) and <code>latest-mac.yml</code></li>
  <li>Windows <code>.exe</code> and <code>latest.yml</code></li>
  <li><code>install.sh</code> and <code>install.ps1</code></li>
</ul>

<h2 id="signing">Optional signing</h2>
<p>A platform is signed when all its secrets are set in the <code>release</code> environment. Otherwise it's a free build.</p>
${table(
  ['Platform', 'Secrets'],
  [
    ['macOS', '<code>MAC_CSC_LINK</code>, <code>MAC_CSC_KEY_PASSWORD</code>, <code>MAC_PROVISIONING_PROFILE_B64</code>, <code>APPLE_ID</code>, <code>APPLE_APP_SPECIFIC_PASSWORD</code>, <code>APPLE_TEAM_ID</code>'],
    ['Windows', '<code>WIN_CSC_LINK</code>, <code>WIN_CSC_KEY_PASSWORD</code>'],
  ],
)}
<p>Set <code>REQUIRE_SIGNED_RELEASE=true</code> to fail instead of falling back to a free build.</p>`,
  },

  // ────────────────────────────────── API ──────────────────────────────────
  {
    id: 'how-the-api-works',
    group: 'API',
    title: 'How the API works',
    description: 'Conventions, proofs, pairing, signing and request auth.',
    body: () => `
<p class="lede">The agent calls your server under <code>&lt;origin&gt;/signature/agent</code>, as JSON over HTTPS. Every proof uses one
message format, so one verifier serves everything.</p>

<h2 id="conventions">Conventions</h2>
<ul>
  <li>Public keys and signatures: base64. Nonces and tokens: base64url, no padding.</li>
  <li>Hashes: lowercase hex SHA-256.</li>
  <li>Every request sends <code>X-Agent-Version</code>. Too old → <code>426 agent_outdated</code>.</li>
  <li>Errors: <code>{"error":{"code","message"}}</code> with a 4xx status. The agent shows <code>message</code>.</li>
  <li>Never redirect these routes. The agent refuses redirects.</li>
</ul>

<h2 id="proof-message">Proof message</h2>
${plain('v1|<purpose>|<nonce>|<user_id>|<payload_hash>')}
${table(
  ['Purpose', 'Key', '<code>payload_hash</code>'],
  [
    ['<code>register_agent</code>', 'Identity', '<code>sha256(identity_spki ‖ session_spki)</code>'],
    ['<code>sign_receipt</code>', 'Identity', 'The document hash'],
    ['<code>request</code>', 'Session', '<code>sha256("METHOD|path|body|timestamp")</code>'],
  ],
)}
<p>Signatures are ES256 (DER) or RS256 (Windows Hello). Both verify with <code>openssl_verify(…, OPENSSL_ALGO_SHA256)</code>.</p>

<h2 id="pairing">Pairing</h2>
${steps([
  '<strong>Web</strong> creates a pairing and shows an 8-character code.',
  '<strong>Agent</strong> looks up the code → <a href="#/api/http/post-pairings-lookup"><code>POST /pairings/lookup</code></a>',
  '<strong>Agent</strong> creates keys and signs <code>register_agent</code> → <a href="#/api/http/post-pairings-claim"><code>POST /pairings/{id}/claim</code></a>',
  '<strong>Web</strong> asks the user to confirm the computer.',
  '<strong>Agent</strong> polls and receives its token once → <a href="#/api/http/post-pairings-poll"><code>POST /pairings/{id}/poll</code></a>',
])}
<p><strong>One signature per app, per computer.</strong> A computer can be paired with many apps, but holds only one
account’s signature for each. Pairing a different account for an app on the same computer is refused: by the agent
before it creates any key (<code>app_already_paired</code>), and by the server at claim
(<code>409 machine_already_paired</code>, matched on <code>hardware_id_hash</code>). The same account pairing again
updates its existing device in place: same uuid and history, new keys (<code>rebound: true</code>). Virtual machines are
refused by default (<code>422 device_type_not_allowed</code>).</p>
${httpCall({
  method: 'POST',
  path: '/signature/agent/pairings/lookup',
  request: '{ "user_code": "K7QM-2XPD" }',
  response: `{
  "pairing": "9f1c…",
  "nonce": "Hk3x…",
  "user_id": "42",
  "server": { "id": "dict", "name": "DICT Signing", "origin": "https://sign.dict.gov.ph", "salt": "…" },
  "require_presence": true,
  "blocked_device_types": ["virtual_machine"],
  "expires_at": "2026-10-01T09:10:00Z"
}`,
})}

<h2 id="signing">Signing a document</h2>
${steps([
  '<strong>Web</strong> creates a job and opens the link below.',
  '<strong>Agent</strong> claims the job with the one-time token → <a href="#/api/http/post-jobs-claim"><code>POST /jobs/{id}/claim</code></a>',
  '<strong>User</strong> approves; the identity key signs <code>sign_receipt</code>.',
  '<strong>Agent</strong> sends the proof → <a href="#/api/http/post-jobs-complete"><code>POST /jobs/{id}/complete</code></a>',
])}
${urlBar('kukuxsign://job/0b7a4f5e-1c2d-4e3f-8a9b-0c1d2e3f4a5b?t=fIb2Bzv4gKtSWoDpD9canXJryrxB47J3uR9y4Xkqz8w&s=dict', 'Job id, one-time token, and the paired server id. Nothing else is accepted.')}

<h2 id="request-auth">Authenticated requests</h2>
<p>After pairing, every call carries a bearer token and a session-key signature:</p>
${plain(
  `Authorization: Bearer <agent token>
X-Agent-Timestamp: 1767225600
X-Agent-Nonce: <b64url, 16+ random bytes>
X-Agent-Proof: <session-key signature of v1|request|nonce|user_id|sha256("METHOD|path|body|timestamp")>`,
  'http',
)}
<p>Reject with <code>401</code> when the token is unknown, the timestamp is off by more than 60 s, the nonce was seen, or the
proof fails. On 401 the agent forgets the pairing.</p>
${editor('src/main/api.ts', 'ts', `const message = canonicalMessage('request', nonce, creds.userId,
  requestPayloadHash(method, pathWithQuery, body, timestamp));
headers['X-Agent-Proof'] = (await creds.signWithSessionKey(Buffer.from(message))).toString('base64');`)}

<p>Next: <a href="#/server-integration">implement it in Laravel</a>, or browse the <a href="#/api/http">endpoint reference</a>.</p>`,
  },
  {
    id: 'server-integration',
    group: 'API',
    title: 'Server integration',
    description: 'What the Laravel package must check, with PHP examples.',
    body: () => `
<p class="lede"><code>test/support/mock-server.ts</code> is a runnable reference: it makes every check below.</p>

<h2 id="verify-proof">Verify a proof</h2>
${editor('app/Support/AgentProof.php', 'php', r`
final class AgentProof
{
    public static function message(string $purpose, string $nonce, string $userId, string $payloadHash): string
    {
        return "v1|{$purpose}|{$nonce}|{$userId}|{$payloadHash}";
    }

    public static function verify(string $message, string $signatureB64, string $spkiB64): bool
    {
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($spkiB64, 64) . "-----END PUBLIC KEY-----\n";

        return openssl_verify($message, base64_decode($signatureB64), $pem, OPENSSL_ALGO_SHA256) === 1;
    }
}`)}

<h2 id="authenticate-agent">Authenticate agent requests</h2>
${editor('app/Http/Middleware/AuthenticateAgent.php', 'php', r`
public function handle(Request $request, Closure $next)
{
    $device = AgentDevice::findByToken($request->bearerToken()) ?? abort(401);

    $timestamp = (int) $request->header('X-Agent-Timestamp');
    abort_if(abs(time() - $timestamp) > 60, 401, 'stale_request');

    $nonce = $request->header('X-Agent-Nonce');
    abort_unless(Cache::add("agent-nonce:{$device->id}:{$nonce}", true, 120), 401, 'replayed_request');

    $hash = hash('sha256', "{$request->method()}|{$request->getRequestUri()}|{$request->getContent()}|{$timestamp}");
    $message = AgentProof::message('request', $nonce, (string) $device->user_id, $hash);
    abort_unless(AgentProof::verify($message, $request->header('X-Agent-Proof'), $device->session_public_key), 401);

    return $next($request->merge(['agent_device' => $device]));
}`)}

<h2 id="pairing-checks">Pairing checks</h2>
<ul>
  <li><code>lookup</code>: unknown, used or expired code → <code>404 invalid_code</code>. Throttle hard.</li>
  <li><code>server.origin</code> must equal the URL the agent called. <code>server.id</code> must never change.</li>
  <li><code>claim</code>: verify the <code>register_agent</code> proof; if presence is required and missing → <code>422 presence_required</code>.</li>
  <li><code>claim</code>: a blocked <code>device_type</code>, or <code>virtual: true</code> while VMs are blocked → <code>422 device_type_not_allowed</code>.</li>
  <li><code>claim</code>: another account’s active agent device with the same <code>hardware_id_hash</code> → <code>409 machine_already_paired</code>, without naming them. The same account’s → return it as <code>existing_device</code>.</li>
  <li><code>confirm</code>: check the computer again under a lock, and back it with a unique index on the hash of active agent devices. Same account → update that device (new keys, old token revoked).</li>
  <li><code>poll</code>: issue the token once, store only its hash. Later polls → <code>409 token_already_issued</code>. Include <code>rebound</code>.</li>
  <li><code>DELETE /device</code> may arrive late: the agent retries revokes that failed offline. A 401 tells it the device is already gone.</li>
</ul>

<h2 id="job-checks">Job checks</h2>
<ul>
  <li><code>claim</code>: pending, unexpired, same user, matching token hash. Then invalidate the token. Again → <code>409 job_unavailable</code>.</li>
  <li><code>complete</code>: claimed by this device; the proof verifies with its identity key. Then set <code>device_id</code> on the signature.</li>
</ul>

<h2 id="config">Config</h2>
${editor('config/signature.php', 'php', r`
'agent' => [
    'enabled'          => env('SIGNATURE_AGENT_ENABLED', false),
    'download_url'     => env('SIGNATURE_AGENT_DOWNLOAD_URL'),
    'min_version'      => '1.0.0',
    'require_presence' => true,
    'job_ttl'          => 300,
    'pairing_ttl'      => 600,
    'blocked_device_types' => ['virtual_machine'],
],`)}`,
  },
];
