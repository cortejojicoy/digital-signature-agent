// Code blocks for the docs site. Each language gets the window it's usually
// read in: shell commands in a macOS Terminal, PowerShell in Windows
// Terminal, source files in an editor tab with the language's badge, API calls
// as a request/response panel, and kukuxsign:// links in an address bar.

export function esc(text) {
  return String(text ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ── Highlighter: one ordered regex per language, tokens become tok-* spans ──

const STR = String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"`;
const NUM = String.raw`\b\d+(?:\.\d+)?\b`;
const FN = String.raw`\b[A-Za-z_]\w*(?=\s*\()`;
const words = (list) => String.raw`\b(?:${list.split(' ').join('|')})\b`;

const RULES = {
  ts: [
    ['c', String.raw`\/\/.*|\/\*[\s\S]*?\*\/`],
    ['s', STR + '|`(?:\\\\.|[^`\\\\])*`'],
    ['k', words('import export from const let var function return async await if else for of in new class extends interface type implements throw try catch finally switch case default break continue typeof instanceof void null undefined true false this readonly private public static as satisfies')],
    ['n', NUM],
    ['fn', FN],
    ['t', String.raw`\b[A-Z][A-Za-z0-9]*\b`],
  ],
  php: [
    ['c', String.raw`\/\/.*|#(?!\[).*|\/\*[\s\S]*?\*\/`],
    ['s', STR],
    ['v', String.raw`\$\w+`],
    ['k', words('use namespace class function return if else foreach as new public private protected static fn throw try catch null true false array match readonly abstract extends implements')],
    ['n', NUM],
    ['fn', FN],
    ['t', String.raw`\b[A-Z][A-Za-z0-9]*\b`],
  ],
  json: [
    ['p', String.raw`"(?:\\.|[^"\\])*"(?=\s*:)`],
    ['s', String.raw`"(?:\\.|[^"\\])*"`],
    ['k', words('true false null')],
    ['n', String.raw`-?\b\d+(?:\.\d+)?\b`],
  ],
  bash: [
    ['c', String.raw`(?<=^|\s)#.*`],
    ['s', STR],
    ['v', String.raw`\$\{[^}]+\}|\$\w+`],
    ['fn', String.raw`(?<=^|\|\s*|&&\s*|\(\s*)(?:curl|bash|cd|cp|npm|npx|node|git|php|python3|open|herd|brew|env|sudo|codesign|spctl|xattr)\b`],
    ['f', String.raw`(?<=\s)--?[A-Za-z][\w-]*`],
  ],
  powershell: [
    ['c', String.raw`#.*`],
    ['s', STR],
    ['v', String.raw`\$[\w:]+`],
    ['fn', String.raw`\b(?:[A-Z][a-z]+-[A-Z]\w+|irm|iex|powershell)\b`],
    ['f', String.raw`(?<=\s)-[A-Za-z]\w*`],
  ],
  yaml: [
    ['c', String.raw`(?<=^|\s)#.*`],
    ['p', String.raw`^\s*-?\s*[\w.-]+(?=:)`],
    ['s', STR],
    ['k', words('true false null')],
    ['n', NUM],
  ],
  http: [
    ['k', String.raw`^(?:GET|POST|PUT|PATCH|DELETE)\b`],
    ['p', String.raw`^[\w-]+(?=:)`],
    ['s', String.raw`<[^>\n]+>`],
  ],
  swift: [
    ['c', String.raw`\/\/.*|\/\*[\s\S]*?\*\/`],
    ['s', STR],
    ['k', words('import func let var return if else guard throw throws try catch struct class enum case static private public init self nil true false in')],
    ['n', NUM],
    ['fn', FN],
    ['t', String.raw`\b[A-Z][A-Za-z0-9]*\b`],
  ],
  cpp: [
    ['c', String.raw`\/\/.*|\/\*[\s\S]*?\*\/`],
    ['k', String.raw`^\s*#\w+|` + words('auto const return if else for while struct class namespace using static void bool int nullptr true false new delete try catch throw')],
    ['s', STR + String.raw`|<[\w./]+\.h>`],
    ['n', NUM],
    ['fn', FN],
    ['t', String.raw`\b[A-Z][A-Za-z0-9]*\b`],
  ],
};
RULES.tsx = RULES.ts;
RULES.js = RULES.ts;
RULES.sh = RULES.bash;
RULES.objc = RULES.cpp;

const COMPILED = new Map();
function compiled(lang) {
  if (!COMPILED.has(lang)) {
    const rules = RULES[lang];
    COMPILED.set(lang, rules ? new RegExp(rules.map(([name, re]) => `(?<${name.replace(/\W/g, '')}>${re})`).join('|'), 'gm') : null);
  }
  return COMPILED.get(lang);
}

export function highlight(code, lang) {
  const re = compiled(lang);
  if (!re) return esc(code);
  let out = '';
  let last = 0;
  for (const m of code.matchAll(re)) {
    if (!m[0]) continue;
    const name = Object.keys(m.groups).find((k) => m.groups[k] !== undefined);
    out += esc(code.slice(last, m.index)) + `<span class="tok-${name}">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(code.slice(last));
}

// ── Windows ──

const COPY = '<button class="copy" type="button" aria-label="Copy code">Copy</button>';

/** Editor badges: label and brand colour for each language. */
const BADGES = {
  ts: ['TS', '#3178c6'],
  tsx: ['TSX', '#3178c6'],
  js: ['JS', '#d4a72c'],
  php: ['PHP', '#777bb4'],
  json: ['{ }', '#cb8a1a'],
  yaml: ['YML', '#cb171e'],
  swift: ['SW', '#f05138'],
  cpp: ['C++', '#00599c'],
  objc: ['M', '#438eff'],
  http: ['HTTP', '#2f6fed'],
  text: ['TXT', '#6b7280'],
};

const LANG_NAMES = {
  ts: 'TypeScript',
  tsx: 'TypeScript React',
  js: 'JavaScript',
  php: 'PHP',
  json: 'JSON',
  yaml: 'YAML',
  swift: 'Swift',
  cpp: 'C++',
  objc: 'Objective-C++',
  http: 'HTTP',
  text: 'Plain text',
};

/** A source file in an editor tab, with line numbers. */
export function editor(file, lang, code) {
  const text = code.replace(/^\n|\n\s*$/g, '');
  const [badge, color] = BADGES[lang] ?? BADGES.text;
  const lines = text.split('\n');
  const gutter = lines.map((_, i) => i + 1).join('\n');
  return `<figure class="win editor" data-lang="${esc(lang)}" style="--lang:${color}" data-copy="${esc(text)}">
    <div class="win-bar">
      <span class="lights" aria-hidden="true"><i></i><i></i><i></i></span>
      <span class="tab"><span class="badge-lang">${esc(badge)}</span>${esc(file)}</span>
      <span class="win-meta">${esc(LANG_NAMES[lang] ?? lang)}</span>
      ${COPY}
    </div>
    <div class="editor-body"><pre class="gutter" aria-hidden="true">${gutter}</pre><pre class="src"><code>${highlight(text, lang)}</code></pre></div>
  </figure>`;
}

/**
 * Shell commands. `os: 'mac'` is a macOS Terminal running zsh, `'win'` is
 * Windows Terminal running PowerShell. Lines starting with `#` are comments;
 * lines starting with `> ` are output. Copy takes only the commands.
 */
export function terminal(code, { os = 'mac', title } = {}) {
  const lang = os === 'win' ? 'powershell' : 'bash';
  const lines = code.replace(/^\n|\n\s*$/g, '').split('\n');
  const commands = [];
  const body = lines
    .map((line) => {
      if (line.startsWith('> ')) return `<span class="term-out">${esc(line.slice(2))}</span>`;
      if (/^\s*#/.test(line) || !line.trim()) return `<span class="tok-c">${esc(line)}</span>`;
      if (/^\s/.test(line)) {
        commands.push(line);
        return highlight(line, lang); // continuation of the previous command
      }
      commands.push(line);
      const prompt = os === 'win' ? 'PS C:\\Users\\you>' : '~ %';
      return `<span class="prompt" aria-hidden="true">${esc(prompt)}</span> ${highlight(line, lang)}`;
    })
    .join('\n');

  const bar =
    os === 'win'
      ? `<span class="tab"><span class="ps-icon" aria-hidden="true">&gt;_</span>${esc(title ?? 'Windows PowerShell')}</span>
         <span class="win-controls" aria-hidden="true"><i>—</i><i>▢</i><i>✕</i></span>`
      : `<span class="lights" aria-hidden="true"><i></i><i></i><i></i></span>
         <span class="win-title">${esc(title ?? 'Terminal — zsh')}</span>`;

  return `<figure class="win term term-${os}" data-lang="${lang}" data-copy="${esc(commands.join('\n'))}">
    <div class="win-bar">${bar}${COPY}</div>
    <pre><code>${body}</code></pre>
  </figure>`;
}

/** An API call: the request line, optional headers and body, and the response. */
export function httpCall({ method, path, headers, request, status = '200 OK', response }) {
  const reqText = [`${method} ${path}`, headers ?? '', request ? `\n${request}` : ''].filter(Boolean).join('\n');
  const statusClass = /^2/.test(status) ? 'ok' : 'err';
  return `<figure class="win http" data-lang="http" data-copy="${esc(reqText)}">
    <div class="win-bar">
      <span class="method m-${method.toLowerCase()}">${esc(method)}</span>
      <code class="http-path">${esc(path)}</code>
      ${COPY}
    </div>
    ${headers ? `<pre class="http-headers"><code>${highlight(headers, 'http')}</code></pre>` : ''}
    ${request ? `<div class="http-label">Request</div><pre><code>${highlight(request, 'json')}</code></pre>` : ''}
    ${response !== undefined ? `<div class="http-label">Response <span class="status ${statusClass}">${esc(status)}</span></div><pre><code>${highlight(response, 'json')}</code></pre>` : ''}
  </figure>`;
}

/** A kukuxsign:// (or https://) link in a browser-style address bar. */
export function urlBar(url, caption = '') {
  const m = /^([a-z]+:\/\/)([^/?#]*)([^?#]*)(\?[^#]*)?$/.exec(url);
  const parts = m
    ? `<span class="url-scheme">${esc(m[1])}</span><span class="url-host">${esc(m[2])}</span><span class="url-path">${esc(m[3])}</span>${
        m[4] ? m[4].replace(/([?&])([^=&]+)=([^&]*)/g, (_x, sep, k, v) => `<span class="url-sep">${esc(sep)}</span><span class="url-key">${esc(k)}</span>=<span class="url-val">${esc(v)}</span>`) : ''
      }`
    : esc(url);
  return `<figure class="urlbar" data-copy="${esc(url)}">
    <div class="urlbar-field"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><code>${parts}</code>${COPY}</div>
    ${caption ? `<figcaption>${caption}</figcaption>` : ''}
  </figure>`;
}

/** A plain block (message formats, trees) without window chrome. */
export function plain(code, lang = 'text') {
  const text = code.replace(/^\n|\n\s*$/g, '');
  return `<figure class="plain" data-copy="${esc(text)}">${COPY}<pre><code>${highlight(text, lang)}</code></pre></figure>`;
}
