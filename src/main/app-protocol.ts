// Serves the bundled UI from app://agent/ (desktop-agent-plan.md §7.1).
//
// With the GrantFileProtocolExtraPrivileges fuse off, file:// pages can't load
// from inside app.asar, and a custom scheme is the stricter option anyway:
// only files under dist/renderer are reachable, and the CSP is sent as a real
// response header.
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { protocol } from 'electron';

export const APP_SCHEME = 'app';
export const APP_ORIGIN = 'app://agent';

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
};

const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
  "connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/** Must run before app `ready`. */
export function registerAppScheme(): void {
  protocol.registerSchemesAsPrivileged([{ scheme: APP_SCHEME, privileges: { standard: true, secure: true } }]);
}

export function handleAppScheme(rendererDir: string): void {
  const root = path.resolve(rendererDir);
  protocol.handle(APP_SCHEME, async (request) => {
    const url = new URL(request.url);
    if (url.host !== 'agent' || request.method !== 'GET') return new Response(null, { status: 404 });

    const relative = decodeURIComponent(url.pathname).replace(/^\/+/, '') || 'index.html';
    const file = path.resolve(root, relative);
    if (!file.startsWith(root + path.sep)) return new Response(null, { status: 404 });

    try {
      // Electron's fs reads from inside app.asar.
      const body = await fs.readFile(file);
      return new Response(body, {
        headers: {
          'Content-Type': TYPES[path.extname(file)] ?? 'application/octet-stream',
          'Content-Security-Policy': CSP,
          'X-Content-Type-Options': 'nosniff',
        },
      });
    } catch {
      return new Response(null, { status: 404 });
    }
  });
}

export function appUrl(hash: string): string {
  return `${APP_ORIGIN}/index.html#${hash}`;
}
