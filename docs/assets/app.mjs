// Docs site: hash router, sidebar, "On this page", pager, search, and the
// API reference renderer. Guides live in pages.mjs, reference data in
// reference.mjs, code windows in code.mjs. No build step.
import { editor, esc, httpCall, plain, urlBar } from './code.mjs';
import { groups, pages } from './pages.mjs';
import { BRANCH, REPO, sections } from './reference.mjs';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const content = $('#content');
const sidebarNav = $('#sidebar-nav');
const toc = $('#toc');

// Every page in reading order: guides by group, then the API reference.
const REFERENCE_GROUP = 'Reference';
const allPages = [
  ...groups.flatMap((g) => pages.filter((p) => p.group === g)),
  ...sections.map((s) => ({ id: `api/${s.id}`, group: REFERENCE_GROUP, title: s.title, description: firstSentence(s.intro), section: s })),
];
const byId = new Map(allPages.map((p) => [p.id, p]));

// Reference item id → section, for cross-links and search.
const itemIndex = new Map();
for (const section of sections) {
  for (const group of section.groups) for (const item of group.items) itemIndex.set(item.id, { section, item });
}

// ── Helpers ──

function firstSentence(text) {
  const plainText = String(text).replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/`/g, '');
  return plainText.split(/(?<=\.)\s/)[0];
}

/** Inline Markdown subset used by reference.mjs: `code`, **bold**, [text](href). */
function md(text) {
  return String(text ?? '')
    .split(/(`[^`]+`)/g)
    .map((part) =>
      part.startsWith('`') && part.endsWith('`') && part.length > 1
        ? `<code>${esc(part.slice(1, -1))}</code>`
        : esc(part)
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label, href) => `<a href="${href}">${label}</a>`),
    )
    .join('');
}

function slug(text) {
  return String(text)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s+/g, '-');
}

const sourceUrl = (ref) => `${REPO}/blob/${BRANCH}/${ref}`;
const itemHref = (id) => (itemIndex.has(id) ? `#/api/${itemIndex.get(id).section.id}/${id}` : '#/');

// ── Sidebar ──

function renderSidebar(current) {
  const groupNames = [...groups, REFERENCE_GROUP];
  sidebarNav.innerHTML = groupNames
    .map((g) => {
      const links = allPages
        .filter((p) => p.group === g)
        .map(
          (p) =>
            `<li><a href="#/${p.id}" data-filter="${esc(`${p.title} ${p.description ?? ''}`.toLowerCase())}"${
              p.id === current.id ? ' aria-current="page"' : ''
            }>${esc(p.title)}</a></li>`,
        )
        .join('');
      return `<div class="nav-group"><h2>${esc(g)}</h2><ul>${links}</ul></div>`;
    })
    .join('');
  applyFilter();
}

const filterInput = $('#nav-filter');
function applyFilter() {
  const q = filterInput.value.trim().toLowerCase();
  let any = false;
  for (const group of $$('.nav-group', sidebarNav)) {
    let visible = 0;
    for (const a of $$('a', group)) {
      const show = !q || a.dataset.filter.includes(q);
      a.parentElement.hidden = !show;
      if (show) visible++;
    }
    group.hidden = visible === 0;
    any ||= visible > 0;
  }
  $('#nav-empty').hidden = any;
}
filterInput.addEventListener('input', applyFilter);

// ── Guide pages ──

function renderGuide(page) {
  return `<article class="prose">
    <h1>${esc(page.title)}</h1>
    ${page.description ? `<p class="page-desc">${esc(page.description)}</p>` : ''}
    ${page.body()}
  </article>`;
}

// ── API reference pages ──

function renderItem(item) {
  const head =
    item.kind === 'endpoint'
      ? `<h3 class="item-title" id="${esc(item.id)}" data-toc="${esc(`${item.method} ${item.path.replace('/signature/agent', '')}`)}"><span class="method m-${item.method.toLowerCase()}">${item.method}</span><code class="path">${esc(item.path.replace('/signature/agent', ''))}</code></h3><p class="item-name">${esc(item.name)}</p>`
      : `<h3 class="item-title" id="${esc(item.id)}" data-toc="${esc(item.name)}"><code>${esc(item.name)}</code><span class="kind kind-${esc(item.kind)}">${esc(item.kind)}</span></h3>`;

  let body = `<p>${md(item.summary)}</p>`;
  if (item.kind === 'link') body += urlBar(item.signature);
  else if (item.signature) body += plain(item.signature, 'ts');
  if (item.channel) body += `<p class="meta"><span>IPC channel</span><code>${esc(item.channel)}</code></p>`;
  if (item.auth) body += `<p class="meta"><span>Auth</span>${md(item.auth)}</p>`;

  if (item.params?.length) {
    body += `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Description</th></tr></thead><tbody>${item.params
      .map((p) => `<tr><td><code>${esc(p.name)}</code></td><td><code>${esc(p.type)}</code></td><td>${md(p.desc)}</td></tr>`)
      .join('')}</tbody></table></div>`;
  }
  if (item.kind === 'endpoint' && (item.request || item.response)) {
    body += httpCall({ method: item.method, path: item.path, request: item.request, response: item.response });
  }
  if (item.returns) body += `<h4>Returns</h4>${item.returns.includes('\n') ? plain(item.returns, 'ts') : `<p>${md(item.returns)}</p>`}`;
  if (item.throws) body += `<h4>Throws</h4><p>${md(item.throws)}</p>`;
  if (item.errors?.length) {
    body += `<h4>Errors</h4><div class="table-wrap"><table><thead><tr><th>Status</th><th>Code</th><th>When</th></tr></thead><tbody>${item.errors
      .map((e) => `<tr><td>${esc(e.status)}</td><td><code>${esc(e.code)}</code></td><td>${md(e.when)}</td></tr>`)
      .join('')}</tbody></table></div>`;
  }
  if (item.table?.length) {
    body += `<div class="table-wrap"><table><tbody>${item.table.map(([k, v]) => `<tr><td><code>${esc(k)}</code></td><td>${md(v)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  if (item.notes?.length) body += `<ul class="notes">${item.notes.map((n) => `<li>${md(n)}</li>`).join('')}</ul>`;
  if (item.example) body += editor('example.ts', 'ts', item.example);

  const links = [];
  if (item.client && itemIndex.has(item.client)) links.push(`Client <a href="${itemHref(item.client)}"><code>${esc(itemIndex.get(item.client).item.name)}</code></a>`);
  if (item.endpoint && itemIndex.has(item.endpoint)) {
    const ep = itemIndex.get(item.endpoint).item;
    links.push(`Endpoint <a href="${itemHref(item.endpoint)}"><code>${esc(ep.method)} ${esc(ep.path.replace('/signature/agent', ''))}</code></a>`);
  }
  if (item.source) {
    links.push(`Source <a href="${esc(sourceUrl(item.source))}" target="_blank" rel="noopener"><code>${esc(item.source.replace('#L', ':'))}</code></a>`);
  }

  return `<section class="item">${head}${body}${links.length ? `<footer>${links.join('<span class="sep">·</span>')}</footer>` : ''}</section>`;
}

function renderReference(page) {
  const s = page.section;
  let html = `<article class="prose reference"><h1>${esc(s.title)}</h1><p class="page-desc">${md(s.intro)}</p>`;
  if (s.format) {
    html += `<h2 id="format">Format</h2>${plain(s.format)}`;
    html += `<div class="table-wrap"><table><thead><tr><th>Purpose</th><th>Signed with</th><th><code>payload_hash</code></th></tr></thead><tbody>${s.purposes
      .map((p) => `<tr><td><code>${esc(p.purpose)}</code></td><td>${esc(p.key)}</td><td><code>${esc(p.hash)}</code></td></tr>`)
      .join('')}</tbody></table></div>`;
  }
  for (const group of s.groups) {
    html += `<h2 id="${slug(group.title)}">${esc(group.title)}</h2>`;
    if (group.intro) html += `<p>${md(group.intro)}</p>`;
    if (group.headers) html += plain(group.headers, 'http');
    html += group.items.map(renderItem).join('');
  }
  return `${html}</article>`;
}

// ── Page chrome: breadcrumb, TOC, pager ──

function renderToc(page) {
  const heads = $$('.prose h2[id], .prose h3.item-title[id]', content);
  if (heads.length < 2) {
    toc.innerHTML = '';
    return;
  }
  toc.innerHTML = `<h2>On this page</h2><ul>${heads
    .map((h) => `<li class="lvl-${h.tagName === 'H2' ? 2 : 3}"><a href="#/${page.id}/${h.id}" data-target="${h.id}">${esc(h.dataset.toc ?? h.textContent.replace(/#$/, ''))}</a></li>`)
    .join('')}</ul>`;
}

let observer;
function watchHeadings() {
  observer?.disconnect();
  const links = new Map($$('a[data-target]', toc).map((a) => [a.dataset.target, a]));
  if (!links.size) return;
  observer = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        for (const a of links.values()) a.removeAttribute('aria-current');
        links.get(e.target.id)?.setAttribute('aria-current', 'true');
      }
    },
    { rootMargin: '-72px 0px -70% 0px' },
  );
  for (const id of links.keys()) {
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  }
}

function addAnchors(page) {
  for (const h of $$('.prose h2[id], .prose h3[id]', content)) {
    const a = document.createElement('a');
    a.className = 'anchor';
    a.href = `#/${page.id}/${h.id}`;
    a.setAttribute('aria-label', 'Link to this section');
    a.textContent = '#';
    h.append(a);
  }
}

function pager(page) {
  const i = allPages.indexOf(page);
  const prev = allPages[i - 1];
  const next = allPages[i + 1];
  const link = (p, cls, label) => (p ? `<a class="${cls}" href="#/${p.id}"><span>${label}</span><strong>${esc(p.title)}</strong></a>` : '<span></span>');
  return `<nav class="pager" aria-label="Pagination">${link(prev, 'prev', 'Previous')}${link(next, 'next', 'Next')}</nav>`;
}

// ── Router ──

let currentPageId = null;

function parseRoute() {
  const parts = (location.hash || '#/').replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  if (parts[0] === 'api') return { id: `api/${parts[1] ?? 'http'}`, anchor: parts[2] };
  // Old links from the previous site: #/guide/<id>.
  if (parts[0] === 'guide') return { id: parts[1] === 'protocol' ? 'how-the-api-works' : parts[1] ?? 'introduction', anchor: parts[2] };
  return { id: parts[0] ?? 'introduction', anchor: parts[1] };
}

function scrollToAnchor(anchor) {
  const el = anchor && document.getElementById(anchor);
  if (!el) return false;
  el.scrollIntoView({ block: 'start' });
  if (el.classList.contains('item-title')) {
    el.parentElement.classList.remove('flash');
    void el.offsetWidth;
    el.parentElement.classList.add('flash');
  }
  return true;
}

function route() {
  const { id, anchor } = parseRoute();
  const page = byId.get(id) ?? byId.get('introduction');

  if (page.id === currentPageId) {
    if (!scrollToAnchor(anchor)) window.scrollTo(0, 0);
    return;
  }
  currentPageId = page.id;

  renderSidebar(page);
  content.innerHTML = `
    <div class="breadcrumb"><a href="#/">Docs</a><span>/</span><span>${esc(page.group)}</span></div>
    ${page.section ? renderReference(page) : renderGuide(page)}
    ${pager(page)}
    <p class="edit"><a href="${esc(sourceUrl(page.section ? 'docs/assets/reference.mjs' : 'docs/assets/pages.mjs'))}" target="_blank" rel="noopener">Edit this page on GitHub</a></p>`;
  addAnchors(page);
  renderToc(page);
  watchHeadings();
  for (const a of $$('.topnav a')) {
    const api = page.group === 'API' || page.group === REFERENCE_GROUP;
    const active = { api, install: page.id === 'installation', docs: !api && page.id !== 'installation' }[a.dataset.section];
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  document.title = `${page.title} · Kukux Sign Agent`;
  document.body.classList.remove('nav-open');
  $('.sidebar-toggle').setAttribute('aria-expanded', 'false');
  if (!scrollToAnchor(anchor)) window.scrollTo(0, 0);
}

window.addEventListener('hashchange', route);
route();

// ── Search ──

const overlay = $('.search-overlay');
const searchInput = $('#search-input');
const searchResults = $('#search-results');
let selected = 0;

const searchIndex = [
  ...pages.flatMap((p) => {
    const tmp = document.createElement('div');
    tmp.innerHTML = p.body();
    const headings = $$('h2[id]', tmp).map((h) => ({ href: `#/${p.id}/${h.id}`, title: h.textContent, sub: p.title, hay: `${h.textContent} ${p.title}`.toLowerCase() }));
    return [{ href: `#/${p.id}`, title: p.title, sub: p.group, hay: `${p.title} ${p.description} ${tmp.textContent}`.toLowerCase() }, ...headings];
  }),
  ...[...itemIndex.values()].map(({ section, item }) => ({
    href: itemHref(item.id),
    title: item.kind === 'endpoint' ? `${item.method} ${item.path.replace('/signature/agent', '')}` : item.name,
    sub: `${section.title} · ${item.kind === 'endpoint' ? item.name : item.kind}`,
    hay: [item.name, item.path, item.method, item.signature, item.summary, item.channel].filter(Boolean).join(' ').toLowerCase(),
  })),
];

function runSearch() {
  const terms = searchInput.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const hits = terms.length
    ? searchIndex
        .filter((e) => terms.every((t) => e.hay.includes(t)))
        .map((e) => ({ e, score: e.title.toLowerCase().includes(terms[0]) ? 0 : 1 }))
        .sort((a, b) => a.score - b.score)
        .slice(0, 12)
        .map(({ e }) => e)
    : [];
  selected = 0;
  searchResults.innerHTML = hits
    .map((h, i) => `<li role="option"${i === 0 ? ' aria-selected="true"' : ''}><a href="${h.href}"><strong>${esc(h.title)}</strong><span>${esc(h.sub)}</span></a></li>`)
    .join('');
  $('#search-empty').hidden = hits.length > 0 || terms.length === 0;
}

function openSearch() {
  overlay.hidden = false;
  searchInput.value = '';
  runSearch();
  searchInput.focus();
}
function closeSearch() {
  overlay.hidden = true;
}

$('.search-open').addEventListener('click', openSearch);
searchInput.addEventListener('input', runSearch);
searchInput.addEventListener('keydown', (e) => {
  const items = $$('li', searchResults);
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    if (!items.length) return;
    items[selected]?.removeAttribute('aria-selected');
    selected = (selected + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
    items[selected].setAttribute('aria-selected', 'true');
    items[selected].scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter') {
    $('a', items[selected] ?? document.createElement('li'))?.click();
  }
});
searchResults.addEventListener('click', (e) => {
  if (e.target.closest('a')) closeSearch();
});
overlay.addEventListener('click', (e) => {
  if (e.target === overlay) closeSearch();
});
document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName);
  if (e.key === '/' && !typing) {
    e.preventDefault();
    openSearch();
  } else if (e.key === 'Escape' && !overlay.hidden) {
    closeSearch();
  }
});

// ── Copy, theme, mobile sidebar ──

document.addEventListener('click', async (e) => {
  const button = e.target.closest('.copy');
  if (!button) return;
  const text = button.closest('[data-copy]')?.dataset.copy ?? '';
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Press ⌘C';
  }
  setTimeout(() => (button.textContent = 'Copy'), 1500);
});

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
try {
  applyTheme(localStorage.getItem('theme'));
} catch {}
$('.theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem('theme', next);
  } catch {}
});

$('.sidebar-toggle').addEventListener('click', (e) => {
  const open = document.body.classList.toggle('nav-open');
  e.currentTarget.setAttribute('aria-expanded', String(open));
});
