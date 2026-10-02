// Bundles main, preload and renderer with esbuild into dist/.
import { copyFile, mkdir, rm } from 'node:fs/promises';

import { build } from 'esbuild';

const watch = process.argv.includes('--watch');
const production = process.env.NODE_ENV === 'production';

await rm('dist', { recursive: true, force: true });
await mkdir('dist/renderer', { recursive: true });

const common = {
  bundle: true,
  sourcemap: production ? false : 'inline',
  minify: production,
  logLevel: 'info',
  define: {
    'process.env.NODE_ENV': JSON.stringify(production ? 'production' : 'development'),
    // Set by the release workflow when the platform build is code-signed.
    'process.env.KUKUX_SIGNED_BUILD': JSON.stringify(process.env.KUKUX_SIGNED_BUILD === 'true' ? 'true' : 'false'),
  },
};

await Promise.all([
  build({
    ...common,
    entryPoints: ['src/main/index.ts'],
    outfile: 'dist/main/index.js',
    platform: 'node',
    target: 'node22',
    format: 'cjs',
    external: ['electron', 'electron-updater'],
  }),
  // Sandboxed preloads may only require('electron'); everything else is bundled.
  build({
    ...common,
    entryPoints: ['src/preload/index.ts'],
    outfile: 'dist/preload/index.js',
    platform: 'node',
    target: 'node22',
    format: 'cjs',
    external: ['electron'],
  }),
  build({
    ...common,
    entryPoints: { app: 'src/renderer/main.tsx' },
    outdir: 'dist/renderer',
    platform: 'browser',
    target: 'chrome130',
    format: 'iife',
    jsx: 'automatic',
  }),
]);

await copyFile('src/renderer/index.html', 'dist/renderer/index.html');
// Shown in What's new (src/main/index.ts reads it from dist/).
await copyFile('CHANGELOG.md', 'dist/CHANGELOG.md');

if (watch) console.log('watch mode is not implemented; re-run npm run build');
