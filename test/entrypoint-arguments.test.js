import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { BIN, runNode, freshToken } from './helpers.js';
import { makeSandbox } from './helpers/fault-fs.js';

test('help/version work before any configuration or durable state initialization', async t => {
  const sb = makeSandbox('ts-help-'); t.after(() => sb.remove());
  const env = { HOME: sb.home, USERPROFILE: sb.home, TELESESSION_TARGETS: 'target-1', TELESESSION_INBOX_PREFIX: 'help',
    TELESESSION_TELEPTY_URL: 'http://127.0.0.1:47999', TELESESSION_TELEPTY_TOKEN_FILE: path.join(sb.root, 'must-not-read'), TELESESSION_STATE_DIR: sb.stateDir };
  for (const flag of ['--help', '-h', '--version']) {
    const result = await runNode([BIN, flag], { cwd: sb.project, env });
    assert.equal(result.code, 0); assert.equal(result.log.includes('CONFIG_'), false);
    assert.match(result.log, flag === '--version' ? /^\d+\.\d+\.\d+/ : /Usage: telesession-mcp/);
    assert.equal(fs.existsSync(sb.stateDir), false);
  }
});
test('unexpected arguments refuse before opening durable state or serving MCP', async t => {
  const sb = makeSandbox('ts-args-'); t.after(() => sb.remove());
  const secret = freshToken();
  const env = { HOME: sb.home, USERPROFILE: sb.home, TELESESSION_TARGETS: 'target-1', TELESESSION_INBOX_PREFIX: 'args',
    TELESESSION_TELEPTY_URL: 'http://127.0.0.1:47999', TELESESSION_TELEPTY_TOKEN: secret, TELESESSION_STATE_DIR: sb.stateDir };
  for (const args of [['--install'], ['--token', secret], ['--help', '--install']]) {
    const result = await runNode([BIN, ...args], { cwd: sb.project, env });
    assert.equal(result.code, 2); assert.match(result.log, /ARGS_UNEXPECTED/);
    assert.equal(result.log.includes(secret), false); assert.equal(fs.existsSync(sb.stateDir), false);
  }
});
