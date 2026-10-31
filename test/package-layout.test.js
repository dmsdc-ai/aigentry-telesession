import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { PACKAGE_DIR } from './helpers.js';

test('actual npm tarball contains both executables, runtime modules and linked API contract', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-pack-layout-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const npmCli = process.env.npm_execpath || (process.env.PATH || '').split(path.delimiter)
    .map(dir => path.join(dir, 'npm')).filter(file => fs.existsSync(file))
    .map(file => fs.realpathSync(file)).find(file => file.endsWith('.js'));
  assert.ok(npmCli, 'npm CLI is required for package acceptance');
  const output = execFileSync(process.execPath, [npmCli, 'pack', '--dry-run', '--ignore-scripts', '--offline', '--json'], {
    cwd: PACKAGE_DIR, encoding: 'utf8', env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot || '',
      HOME: root, USERPROFILE: root, npm_config_cache: path.join(root, 'cache'), npm_config_userconfig: path.join(root, 'no-config'),
      npm_config_globalconfig: path.join(root, 'no-global-config'), npm_config_update_notifier: 'false' }
  });
  const [pack] = JSON.parse(output), files = new Set(pack.files.map(file => file.path));
  for (const file of ['bin/telesession-mcp.js', 'bin/telesession-tunnel-child.js', 'src/index.js', 'src/adapters/mcp.js',
    'src/transports/telepty.js', 'README.md', 'API-CONTRACT-TELESESSION.md']) assert.ok(files.has(file), file);
  assert.equal([...files].some(file => /^(node_modules|test|test-support)\//.test(file)), false);
});
