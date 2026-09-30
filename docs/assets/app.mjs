// Docs site: hash router, sidebar, search, and renderers for the API
// reference (reference.mjs) and the Markdown guides in docs/.
import { BRANCH, REPO, guides, sections } from './reference.mjs';

const MARKED_URL = 'https://cdn.jsdelivr.net/npm/marked@12.0.2/lib/marked.esm.js';

const $ = (sel, root = document) => root.querySelector(sel);
const content = $('#content');
const nav = $('#nav');
const search = $('#search');
const results = $('#results');

// id → { section, group, item } for cross-links and search.
const index = new Map();
for (const section of sections) {
  for (const group of section.groups) {
    for (const item of group.items) index.set(item.id, { section, group, item });
  }
}

// ── Helpers ──

function esc(text) {
  return String(text ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** Inline Markdown subset: `code`, **bold**, [text](href). */
function md(text) {
  const parts = String(text ?? '').split(/(`[^`]+`)/g);
  return parts
    .map((part) => {
      if (part.startsWith('`') && part.endsWith('`') && part.length > 1) return `<code>${esc(part.slice(1, -1))}</code>`;
      return esc(part)
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label, href) => `<a href="${href}">${label}</a>`);
    })
    .join('');
}

function sourceUrl(ref) {
  return `${REPO}/blob/${BRANCH}/${ref}`;
}

function sourceLink(ref) {
  if (!ref) return '';
  return `<a class="source" href="${esc(sourceUrl(ref))}" target="_blank" rel="noopener">${esc(ref.replace('#L', ':'))}</a>`;
}

function itemHref(id) {
  const hit = index.get(id);
  return hit ? `#/api/${hit.section.id}/${id}` : '#/';
}

function code(text, lang = '') {
  return `<div class="code"><button class="copy" type="button" aria-label="Copy code">Copy</button><pre${lang ? ` data-lang="${lang}"` : ''}><code>${esc(text)}</code></pre></div>`;
}

function slug(text) {
  return String(text)
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .replace(/\s/g, '-');
}

// ── Sidebar ──

function renderNav(route) {
  const active = (href) => (route.href === href || route.href.startsWith(`${href}/`) ? ' class="active"' : '');
  let html = `<div class="nav-group"><a href="#/"${route.href === '#/' ? ' class="active"' : ''}>Overview</a></div>`;
  html += `<div class="nav-group"><h4>Guides</h4>`;
  for (const g of guides) html += `<a href="#/guide/${g.id}"${active(`#/guide/${g.id}`)}>${esc(g.title)}</a>`;
  html += `</div><div class="nav-group"><h4>API reference</h4>`;
  for (const s of sections) {
    const href = `#/api/${s.id}`;
    html += `<a href="${href}"${active(href)}>${esc(s.title)}</a>`;
    if (route.section === s.id) {
      html += '<div class="nav-sub">';
      for (const group of s.groups) {
        for (const item of group.items) {
          const label = item.kind === 'endpoint' ? `<span class="m m-${item.method.toLowerCase()}">${item.method}</span>${esc(item.path.replace('/signature/agent', ''))}` : esc(item.name);
          html += `<a href="${href}/${item.id}"${route.item === item.id ? ' class="current"' : ''}>${label}</a>`;
        }
      }
      html += '</div>';
    }
  }
  html += '</div>';
  nav.innerHTML = html;
}

// ── Overview ──

function renderOverview() {
  const count = (kind) => [...index.values()].filter((h) => h.item.kind === kind).length;
  const cards = sections
    .map(
      (s) => `<a class="card" href="#/api/${s.id}">
        <h3>${esc(s.title)}</h3>
        <p>${md(s.intro.split('. ')[0])}.</p>
      </a>`,
    )
    .join('');

  content.innerHTML = `
    <section class="hero">
      <p class="eyebrow">Kukux Sign Agent</p>
      <h1>Documentation and API reference</h1>
      <p class="lede">A desktop signing agent for <code>kukux/digital-signature</code>. It keeps signing keys in the
      machine’s security chip (the Secure Enclave on macOS, the TPM with Windows Hello on Windows), pairs them with the
      web app, and proves on each signing that <em>this</em> machine was used, with Touch ID or Windows Hello enforced by the key itself.</p>
      <div class="stats">
        <div><strong>${count('endpoint')}</strong><span>HTTP endpoints</span></div>
        <div><strong>${count('function') + count('method') + count('class')}</strong><span>functions and classes</span></div>
        <div><strong>${count('ipc') + count('event')}</strong><span>bridge calls and events</span></div>
      </div>
    </section>

    <h2>Install</h2>
    ${code('# macOS\ncurl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash')}
    ${code('# Windows (PowerShell, no admin needed)\nirm https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.ps1 | iex')}
    <p>Options, manual installs, MDM rollout and self-hosting are in the <a href="#/guide/installation">Installation guide</a>.</p>

    <h2>How signing works</h2>
    <ol class="flow">
      <li><strong>Pair once.</strong> The user enters the code from the web app. The agent creates an <em>identity key</em>
        (Touch ID / Hello on every use) and a <em>session key</em> (no prompt), signs a <code>register_agent</code> proof, and
        waits for the user to confirm on the web. <a href="#/api/http/post-pairings-lookup">Pairing endpoints</a></li>
      <li><strong>Open a job link.</strong> The web app opens <code>kukuxsign://job/&lt;uuid&gt;?t=…&amp;s=…</code>. The agent
        fetches the job itself from the paired server. <a href="#/api/links">Links</a></li>
      <li><strong>Confirm and sign.</strong> The user approves the document in the agent, then the OS prompt. The identity key
        signs <code>v1|sign_receipt|…</code>. <a href="#/api/canonical">Proof messages</a></li>
      <li><strong>Every call is signed.</strong> Authenticated requests carry a bearer token and an <code>X-Agent-Proof</code>
        from the session key, so a leaked token alone is useless. <a href="#/api/http/get-status">Authenticated calls</a></li>
    </ol>

    <h2>Reference</h2>
    <div class="cards">${cards}</div>
  `;
}

// ── API section ──

function renderItem(item) {
  const head =
    item.kind === 'endpoint'
      ? `<h3 class="item-title"><span class="m m-${item.method.toLowerCase()}">${item.method}</span><code class="path">${esc(item.path)}</code></h3><p class="item-name">${esc(item.name)}</p>`
      : `<h3 class="item-title"><code>${esc(item.name)}</code><span class="kind">${esc(item.kind)}</span></h3>`;

  let body = `<p>${md(item.summary)}</p>`;
  if (item.signature) body += code(item.signature, 'ts');
  if (item.channel) body += `<p class="meta"><span>IPC channel</span> <code>${esc(item.channel)}</code></p>`;
  if (item.auth) body += `<p class="meta"><span>Auth</span> ${md(item.auth)}</p>`;

  if (item.params?.length) {
    body += `<div class="table-wrap"><table class="params"><thead><tr><th>${item.kind === 'endpoint' || item.kind === 'link' ? 'Parameter' : 'Name'}</th><th>Type</th><th>Description</th></tr></thead><tbody>`;
    for (const p of item.params) body += `<tr><td><code>${esc(p.name)}</code></td><td><code>${esc(p.type)}</code></td><td>${md(p.desc)}</td></tr>`;
    body += '</tbody></table></div>';
  }
  if (item.request) body += `<h4>Request body</h4>${code(item.request, 'json')}`;
  if (item.response) body += `<h4>Response</h4>${code(item.response, 'json')}`;
  if (item.returns) body += `<h4>Returns</h4>${item.returns.includes('\n') ? code(item.returns, 'ts') : `<p>${md(item.returns)}</p>`}`;
  if (item.throws) body += `<h4>Throws</h4><p>${md(item.throws)}</p>`;

  if (item.errors?.length) {
    body += '<h4>Errors</h4><div class="table-wrap"><table class="params"><thead><tr><th>Status</th><th>Code</th><th>When</th></tr></thead><tbody>';
    for (const e of item.errors) body += `<tr><td>${esc(e.status)}</td><td><code>${esc(e.code)}</code></td><td>${md(e.when)}</td></tr>`;
    body += '</tbody></table></div>';
  }
  if (item.table?.length) {
    body += '<div class="table-wrap"><table class="params"><tbody>';
    for (const [k, v] of item.table) body += `<tr><td><code>${esc(k)}</code></td><td>${md(v)}</td></tr>`;
    body += '</tbody></table></div>';
  }
  if (item.notes?.length) body += `<ul class="notes">${item.notes.map((n) => `<li>${md(n)}</li>`).join('')}</ul>`;
  if (item.example) body += `<h4>Example</h4>${code(item.example, 'ts')}`;

  const links = [];
  if (item.client && index.has(item.client)) links.push(`<span>Client: <a href="${itemHref(item.client)}"><code>${esc(index.get(item.client).item.name)}</code></a></span>`);
  if (item.endpoint && index.has(item.endpoint)) {
    const ep = index.get(item.endpoint).item;
    links.push(`<span>Endpoint: <a href="${itemHref(item.endpoint)}"><code>${esc(ep.method)} ${esc(ep.path)}</code></a></span>`);
  }
  if (item.source) links.push(`<span>Source: ${sourceLink(item.source)}</span>`);

  return `<article class="item" id="${esc(item.id)}">
    <a class="anchor" href="${itemHref(item.id)}" aria-label="Link to ${esc(item.name)}">#</a>
    ${head}${body}
    ${links.length ? `<footer>${links.join('<span class="sep">·</span>')}</footer>` : ''}
  </article>`;
}

function renderSection(section, itemId) {
  let html = `<header class="page-head"><p class="eyebrow">API reference</p><h1>${esc(section.title)}</h1><p class="lede">${md(section.intro)}</p></header>`;

  if (section.format) {
    html += `<h2>Format</h2>${code(section.format)}`;
    html += '<div class="table-wrap"><table class="params"><thead><tr><th>Purpose</th><th>Signed with</th><th><code>payload_hash</code></th></tr></thead><tbody>';
    for (const p of section.purposes) html += `<tr><td><code>${esc(p.purpose)}</code></td><td>${esc(p.key)}</td><td><code>${esc(p.hash)}</code></td></tr>`;
    html += '</tbody></table></div>';
  }

  for (const group of section.groups) {
    html += `<h2 id="g-${slug(group.title)}">${esc(group.title)}</h2>`;
    if (group.intro) html += `<p>${md(group.intro)}</p>`;
    if (group.headers) html += code(group.headers, 'http');
    html += group.items.map(renderItem).join('');
  }
  content.innerHTML = html;

  if (itemId) {
    const target = document.getElementById(itemId);
    if (target) {
      target.scrollIntoView({ block: 'start' });
      target.classList.add('flash');
      return true;
    }
  }
  return false;
}

// ── Guides ──

let markedPromise;
function loadMarked() {
  markedPromise ??= import(MARKED_URL).then((m) => m.marked).catch(() => null);
  return markedPromise;
}

/** Rewrites links in a rendered guide so they work on the site. */
function fixGuideLinks(root, guide) {
  const byFile = new Map(guides.map((g) => [g.file, g.id]));
  for (const a of root.querySelectorAll('a[href]')) {
    const href = a.getAttribute('href');
    if (/^[a-z]+:/i.test(href)) {
      a.target = '_blank';
      a.rel = 'noopener';
      continue;
    }
    if (href.startsWith('#')) {
      a.setAttribute('href', `#/guide/${guide.id}/${href.slice(1)}`);
      continue;
    }
    const [file, frag] = href.split('#');
    if (byFile.has(file)) {
      a.setAttribute('href', `#/guide/${byFile.get(file)}${frag ? `/${frag}` : ''}`);
      continue;
    }
    // Anything else is a repo file relative to docs/.
    const resolved = new URL(file, 'https://x/docs/').pathname.replace(/^\//, '');
    a.setAttribute('href', `${REPO}/blob/${BRANCH}/${resolved}${frag ? `#${frag}` : ''}`);
    a.target = '_blank';
    a.rel = 'noopener';
  }
}

async function renderGuide(guide, anchor) {
  content.innerHTML = `<p class="loading">Loading ${esc(guide.title)}…</p>`;
  let text;
  try {
    const res = await fetch(guide.file);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    text = await res.text();
  } catch (err) {
    content.innerHTML = `<div class="callout">Couldn’t load <code>${esc(guide.file)}</code> (${esc(err.message)}). <a href="${esc(sourceUrl(`docs/${guide.file}`))}">Read it on GitHub</a>.</div>`;
    return false;
  }

  const marked = await loadMarked();
  if (!marked) {
    content.innerHTML = `<div class="callout">The Markdown renderer didn’t load, so this is the raw text.</div><pre class="raw">${esc(text)}</pre>`;
    return false;
  }

  content.innerHTML = `<article class="prose">${marked.parse(text, { gfm: true })}</article>
    <p class="edit">${sourceLink(`docs/${guide.file}`)}</p>`;
  const article = $('.prose', content);
  for (const h of article.querySelectorAll('h1, h2, h3, h4')) h.id = slug(h.textContent);
  for (const pre of article.querySelectorAll('pre')) {
    const wrap = document.createElement('div');
    wrap.className = 'code';
    wrap.innerHTML = '<button class="copy" type="button" aria-label="Copy code">Copy</button>';
    pre.replaceWith(wrap);
    wrap.append(pre);
  }
  for (const table of article.querySelectorAll('table')) {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    table.replaceWith(wrap);
    wrap.append(table);
  }
  fixGuideLinks(article, guide);

  if (anchor) {
    const target = document.getElementById(anchor);
    if (target) {
      target.scrollIntoView({ block: 'start' });
      return true;
    }
  }
  return false;
}

// ── Search ──

const searchable = [...index.values()].map(({ section, item }) => {
  const path = item.path?.replace('/signature/agent', '');
  return {
    href: itemHref(item.id),
    label: item.kind === 'endpoint' ? `${item.method} ${item.path}` : item.name,
    sub: `${section.title} · ${item.kind === 'endpoint' ? item.name : item.kind}`,
    name: [item.name, path].filter(Boolean).join(' ').toLowerCase(),
    hay: [item.name, path, item.method, item.signature, item.summary, item.channel, item.kind].filter(Boolean).join(' ').toLowerCase(),
  };
});

/** Lower is better: exact name, name prefix, word in name, anywhere. */
function rank(entry, term) {
  const short = entry.name.split(' ')[0].split('.').pop();
  if (short === term) return 0;
  if (short.startsWith(term)) return 1;
  if (entry.name.includes(term)) return 2;
  return 3;
}

function runSearch() {
  const q = search.value.trim().toLowerCase();
  if (!q) {
    results.hidden = true;
    results.innerHTML = '';
    return;
  }
  const terms = q.split(/\s+/);
  const hits = searchable
    .filter((s) => terms.every((t) => s.hay.includes(t)))
    .map((s, i) => ({ s, i, r: rank(s, terms[0]) }))
    .sort((a, b) => a.r - b.r || a.i - b.i)
    .map(({ s }) => s)
    .slice(0, 12);
  results.innerHTML = hits.length
    ? hits.map((h) => `<a href="${h.href}"><strong>${esc(h.label)}</strong><span>${esc(h.sub)}</span></a>`).join('')
    : '<p class="empty">No matches</p>';
  results.hidden = false;
}

search.addEventListener('input', runSearch);
search.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('a', results)?.click();
  if (e.key === 'Escape') {
    search.value = '';
    runSearch();
    search.blur();
  }
});
results.addEventListener('click', () => {
  search.value = '';
  runSearch();
});
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== search) {
    e.preventDefault();
    search.focus();
  }
});

// ── Copy buttons, theme, mobile nav ──

document.addEventListener('click', async (e) => {
  const button = e.target.closest('.copy');
  if (!button) return;
  const text = button.parentElement.querySelector('pre')?.innerText ?? '';
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Press ⌘C';
  }
  setTimeout(() => (button.textContent = 'Copy'), 1500);
});

const themeButton = $('#theme');
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
try {
  applyTheme(localStorage.getItem('theme'));
} catch {}
themeButton.addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  const next = dark ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem('theme', next);
  } catch {}
});

$('#menu').addEventListener('click', () => document.body.classList.toggle('nav-open'));
nav.addEventListener('click', (e) => {
  if (e.target.closest('a')) document.body.classList.remove('nav-open');
});

// ── Router ──

function parseRoute() {
  const hash = location.hash || '#/';
  const [, kind, id, sub] = hash.split('/');
  return { href: hash, kind, id, sub };
}

async function route() {
  const r = parseRoute();
  let scrolled = false;
  const view = { href: r.href, section: null, item: null };

  if (r.kind === 'api' && sections.some((s) => s.id === r.id)) {
    const section = sections.find((s) => s.id === r.id);
    view.section = section.id;
    view.item = r.sub ?? null;
    renderNav(view);
    scrolled = renderSection(section, r.sub);
    document.title = `${section.title} · Kukux Sign Agent`;
  } else if (r.kind === 'guide' && guides.some((g) => g.id === r.id)) {
    const guide = guides.find((g) => g.id === r.id);
    renderNav(view);
    document.title = `${guide.title} · Kukux Sign Agent`;
    scrolled = await renderGuide(guide, r.sub ? decodeURIComponent(r.sub) : null);
  } else {
    view.href = '#/';
    renderNav(view);
    renderOverview();
    document.title = 'Kukux Sign Agent docs';
  }
  if (!scrolled) window.scrollTo(0, 0);
}

window.addEventListener('hashchange', route);
route();
