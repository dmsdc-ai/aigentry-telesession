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
  for (const file of ['bin/telesession-mcp.js', 'bin/telesession-tunnel-child.js', 'bin/telesession-relay-tick.js', 'bin/telesession-ledger-prune.js', 'src/index.js', 'src/adapters/mcp.js',
    'src/transports/telepty.js', 'README.md', 'API-CONTRACT-TELESESSION.md', 'CHANGELOG.md']) assert.ok(files.has(file), file);
  assert.equal([...files].some(file => /^(node_modules|test|test-support)\//.test(file)), false);
  // Dated operational reports and repository status/CI records are evidence, not public payload.
  assert.equal([...files].some(file => /^docs\/(2026-10-31-|status\.md$|ci\.md$|contract-clarification)/.test(file)), false);
  // Exact public payload (RELEASE-FILES.json inventory); any addition or removal is a reviewed change.
  assert.deepEqual([...files].sort(), ['API-CONTRACT-TELESESSION.md', 'CHANGELOG.md', 'LICENSE', 'README.md',
    'bin/telesession-ledger-prune.js', 'bin/telesession-mcp.js', 'bin/telesession-relay-tick.js', 'bin/telesession-tunnel-child.js',
    'docs/architecture.md', 'docs/install.md', 'docs/specs/2026-10-11-e2e-delivery-protocol.md', 'docs/tunnel-child.md',
    'package.json', 'src/adapters/mcp.js', 'src/config.js', 'src/index.js', 'src/relay/adapters.js', 'src/relay/ledger.js',
    'src/relay/relay.js', 'src/relay/route.js', 'src/relay/runner.js', 'src/store.js', 'src/transports/telepty.js', 'src/tunnel-child.js']);
});
