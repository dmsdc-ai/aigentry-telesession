#!/usr/bin/env node

/**
 * telesession-tunnel-child — fixed stdio entry for a tunnel client: runs the packaged telesession-mcp
 * with the current Node binary and an allowlisted child environment (see docs/tunnel-child.md).
 * Takes no arguments. Never writes to stdout (that byte stream belongs to the MCP child); refusals
 * are one stderr line with a code only.
 */

import { spawn } from "node:child_process";
import { buildSpawnPlan, resolveMcpEntry, runChild } from "../src/tunnel-child.js";

let plan;
try {
  plan = buildSpawnPlan({
    argv: process.argv.slice(2),
    env: process.env,
    platform: process.platform,
    execPath: process.execPath,
    entryPath: resolveMcpEntry(),
  });
} catch (err) {
  process.stderr.write(`telesession-tunnel-child refused: ${(err && err.code) || "TUNNEL_CHILD_INVALID"}\n`);
  process.exit(2);
}

runChild(plan, {
  spawn,
  onDiagnostic: (code) => {
    try { process.stderr.write(`telesession-tunnel-child: ${code}\n`); } catch { /* stderr gone */ }
  },
}).then((code) => process.exit(code), () => process.exit(1));
