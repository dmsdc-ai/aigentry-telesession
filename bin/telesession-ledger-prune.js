#!/usr/bin/env node

/**
 * telesession-ledger-prune — DRY RUN ONLY (SPEC 2026-10-11 §6 retention). Lists what an operator prune
 * would delete: retired records (with their reply-file count) and quarantined outbox items. Nothing is
 * deleted; without `--dry-run` it refuses (PRUNE_DRY_RUN_ONLY, exit 2). Reads TELESESSION_STATE_DIR only
 * and opens <state dir>/ledger read-only (review 3 B1): no lock file, no open-time recovery or sweep, no
 * write. A held or stale lock is refused with exit 3 (never reclaimed); a missing ledger dir too.
 */

import path from "node:path";
import { openLedger } from "../src/relay/ledger.js";

const refuse = (code, exit) => {
  process.stderr.write(`telesession-ledger-prune refused: ${code}\n`);
  process.exit(exit);
};

const args = process.argv.slice(2);
if (args.length !== 1 || args[0] !== "--dry-run") refuse("PRUNE_DRY_RUN_ONLY", 2);
const stateDir = process.env.TELESESSION_STATE_DIR;
if (typeof stateDir !== "string" || !path.isAbsolute(stateDir) || path.normalize(stateDir) !== stateDir) refuse("CONFIG_STATE_DIR_INVALID", 2);

let ledger;
try { ledger = openLedger({ dir: path.join(stateDir, "ledger"), readOnly: true }); } catch (err) { refuse((err && err.code) || "LEDGER_OPEN_FAILED", 3); }
try {
  const p = ledger.prunable();
  process.stdout.write(`${JSON.stringify({ dry_run: true, records: p.records, outbox: p.outbox })}\n`);
} finally {
  ledger.close();
}
