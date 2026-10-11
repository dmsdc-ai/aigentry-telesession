#!/usr/bin/env node

/**
 * telesession-relay-tick — ONE relay tick (SPEC 2026-10-11 §10), for an operator when no telesession MCP
 * process owns the ledger. Config from TELESESSION_* env (README.md); the ledger is <state dir>/ledger.
 * The ledger lock is taken BEFORE any telepty request: a lock held by a live process (LEDGER_LOCKED) or
 * left by a dead one (LEDGER_LOCK_STALE) is refused with exit 3 and never reclaimed. No loop, no timer.
 * stdout: the tick result as one JSON line. Exit 0 = tick ran, 1 = tick failed, 2 = config, 3 = ledger.
 */

import path from "node:path";
import { loadConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";

const refuse = (code, exit) => {
  process.stderr.write(`telesession-relay-tick refused: ${code}\n`);
  process.exit(exit);
};

let cfg;
try { cfg = loadConfig(process.env); } catch (err) { refuse((err && err.code) || "CONFIG_INVALID", 2); }
if (cfg.stateDir === null) refuse("LEDGER_NOT_CONFIGURED", 2);

let ledger;
try { ledger = openLedger({ dir: path.join(cfg.stateDir, "ledger") }); } catch (err) { refuse((err && err.code) || "LEDGER_OPEN_FAILED", 3); }

let transport;
try { transport = createTeleptyTransport(cfg, undefined, { ledger }); } catch (err) {
  ledger.close();
  refuse((err && err.code) || "TRANSPORT_INIT_FAILED", 2);
}

let code = 1;
try {
  const r = await transport.relayTick();
  process.stdout.write(`${JSON.stringify(r)}\n`);
  code = r.ok ? 0 : 1;
} finally {
  try { await transport.close(); } catch { /* best effort */ }
  ledger.close();
}
process.exit(code);
