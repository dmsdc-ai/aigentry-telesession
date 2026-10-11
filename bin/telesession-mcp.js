#!/usr/bin/env node

/**
 * telesession-mcp — local stdio MCP server over the telesession telepty transport.
 * Config comes from TELESESSION_* env only (see README.md). This is a local adapter; it does not
 * create a remote (e.g. ChatGPT/Dot) MCP connection by itself.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "node:fs";
import path from "node:path";
import { loadConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { registerMcpTools } from "../src/adapters/mcp.js";

const PKG_VERSION = (() => {
  try {
    const p = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    return p.version || "0.0.0";
  } catch { return "0.0.0"; }
})();

// Fail closed BEFORE any telepty request: exit 2 with a code only (no env values, no token, no
// state dir path). ConfigError and StoreError (e.g. STORE_LOCKED after an abrupt crash) take this path.
let transport;
try {
  const cfg = loadConfig(process.env);
  // Durable mode only: the correlation ledger lives inside the (locked, private) state dir. A ledger that
  // cannot open leaves every existing tool unchanged; request_status then reports LEDGER_NOT_CONFIGURED.
  const ledger = cfg.stateDir === null ? undefined : () => openLedger({ dir: path.join(cfg.stateDir, "ledger") });
  transport = createTeleptyTransport(cfg, undefined, { ledger });
} catch (err) {
  process.stderr.write(`telesession-mcp refused: ${(err && err.code) || "CONFIG_INVALID"}\n`);
  process.exit(2);
}

const server = new McpServer({ name: "telesession", version: PKG_VERSION });
registerMcpTools(server, transport);

// The inbox lives exactly as long as this stdio session; one stderr line reports the outcome.
function bindProcessLifetime(stdin) {
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    transport.close()
      .then((r) => {
        const detail = r.code ? ` (${r.code})` : "";
        const pending = r.outcome === "retained" || r.outcome === "registration_unknown" ? ", operator cleanup pending" : "";
        try { process.stderr.write(`telesession: inbox ${r.inbox_id} ${r.outcome}${detail}${pending}\n`); } catch { /* stderr gone */ }
      })
      .catch(() => {})
      .finally(() => process.exit(0));
  };
  stdin.once("end", stop);
  stdin.once("close", stop);
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  // Terminal/console hang-up: same graceful close. `on` + the `stopping` guard keep a repeated SIGHUP
  // from interrupting cleanup. Not every platform delivers it; abrupt kills are never cleaned up here.
  try { process.on("SIGHUP", stop); } catch { /* signal not supported on this platform */ }
}

async function main() {
  await server.connect(new StdioServerTransport());
  bindProcessLifetime(process.stdin);
}

main().catch(() => {
  process.stderr.write("telesession-mcp: fatal: MCP_START_FAILED\n");
  transport.close().catch(() => {}).finally(() => process.exit(1));
});
