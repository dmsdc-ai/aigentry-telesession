#!/usr/bin/env node

/**
 * telesession-mcp — local stdio MCP server over the telesession telepty transport.
 * Config comes from TELESESSION_* env only (see README.md). This is a local adapter; it does not
 * create a remote (e.g. ChatGPT/Dot) MCP connection by itself.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "node:fs";
import { loadConfig, createTeleptyTransport } from "../src/index.js";
import { registerMcpTools } from "../src/adapters/mcp.js";

const PKG_VERSION = (() => {
  try {
    const p = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    return p.version || "0.0.0";
  } catch { return "0.0.0"; }
})();

// CLI questions must not initialize configuration, a durable store or MCP.
const args = process.argv.slice(2);
if (args.length === 1 && ["--help", "-h"].includes(args[0])) {
  process.stdout.write("Usage: telesession-mcp [--help | --version]\nRun without arguments to serve MCP over stdio.\n" +
    "Configure TELESESSION_TARGETS, TELESESSION_INBOX_PREFIX, TELESESSION_TELEPTY_URL, and exactly one of TELESESSION_TELEPTY_TOKEN_FILE or TELESESSION_TELEPTY_TOKEN.\n" +
    "Requires Node >=20 and a compatible local Telepty daemon; never installs, enrolls, restarts or hosts a remote gateway.\n");
  process.exit(0);
}
if (args.length === 1 && args[0] === "--version") {
  process.stdout.write(`${PKG_VERSION}\n`);
  process.exit(0);
}
if (args.length !== 0) {
  process.stderr.write("telesession-mcp refused: ARGS_UNEXPECTED (use --help)\n");
  process.exit(2);
}

// Fail closed BEFORE any telepty request: exit 2 with a code only (no env values, no token, no
// state dir path). ConfigError and StoreError (e.g. STORE_LOCKED after an abrupt crash) take this path.
let transport;
try {
  transport = createTeleptyTransport(loadConfig(process.env));
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
