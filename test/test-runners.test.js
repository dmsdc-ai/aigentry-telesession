// Issue #6 (owner review F2): CI runs `npm run test:unit`, so a test file that no runner script names is never
// measured there. Every test/*.test.js must be named by a runner below, and every named file must exist (`test`,
// the whole directory, does not count). `test:unit` names every file that runs without a real daemon or MCP SDK;
// `test:real-daemon` is the local real-daemon set (needs TELESESSION_TEST_TELEPTY_DIR + the MCP SDK; its
// transport-telepty file is also in test:unit, where its real-daemon block is skipped NOTRUN); `test:e2e` is
// the fake-adapter full-route proof, also in test:unit (daemon-free; review 1 NB1, orchestrator decision).

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const RUNNERS = ["test:unit", "test:real-daemon", "test:e2e"];

test("#6 every test file is named by an npm runner (test:unit, test:real-daemon, test:e2e); every named file exists", () => {
  const scripts = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).scripts || {};
  const named = new Set(RUNNERS.flatMap((r) => (scripts[r] || "").split(/\s+/).filter((w) => /^test\/.+\.test\.js$/.test(w))));
  const files = fs.readdirSync(path.join(ROOT, "test")).filter((n) => n.endsWith(".test.js")).map((n) => `test/${n}`).sort();
  assert.deepEqual(files.filter((f) => !named.has(f)), [], "test files no runner names");
  assert.deepEqual([...named].filter((f) => !files.includes(f)), [], "named files that do not exist");
});
