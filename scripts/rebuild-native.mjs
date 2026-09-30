// Builds native/keystore.node against the pinned Electron's headers.
// The addon uses N-API, so the ABI is stable across Node and Electron; this
// still builds with Electron's toolchain settings for release artifacts.
//
// On macOS it builds arm64 and x64 and merges them with lipo, so the one
// keystore.node works in both the arm64 and the x64 app packages.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { version } = require('electron/package.json');
const output = 'native/build/Release/keystore.node';

function build(arch) {
  execFileSync(
    process.execPath,
    [
      require.resolve('node-gyp/bin/node-gyp.js'),
      'rebuild',
      '--directory=native',
      `--target=${version}`,
      `--arch=${arch}`,
      '--dist-url=https://electronjs.org/headers',
    ],
    { stdio: 'inherit' },
  );
}

if (process.platform === 'darwin' && !process.env.npm_config_arch) {
  const tmp = mkdtempSync(path.join(tmpdir(), 'keystore-'));
  try {
    for (const arch of ['arm64', 'x64']) {
      build(arch);
      copyFileSync(output, path.join(tmp, `${arch}.node`));
    }
    execFileSync('lipo', ['-create', '-output', output, path.join(tmp, 'arm64.node'), path.join(tmp, 'x64.node')], {
      stdio: 'inherit',
    });
    execFileSync('lipo', ['-info', output], { stdio: 'inherit' });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
} else {
  build(process.env.npm_config_arch || process.arch);
}
