# telesession — snapshot status (2026-10-11)

## Current local follow-up (2026-10-31)

The historical table below describes the original snapshot, not current Linux
test results. The isolated consumer repair at5dd2583 passed187/190, zero failed,
three native/platform skips against Telepty source b842f0c, including real private
daemon restart. HTTP/audit uncertainty stays unknown without replay. Later local
install-flow work adds help/version/strict argument refusal and the missing API
contract to the actual tarball. A new offline npm prefix installation and its own
installed MCP SDK/executable completed all-five-tool durable roundtrip/owned close
acceptance. See [installation](install.md) for exact prerequisites and boundaries.

Native macOS/Windows, current Dot/Mac, remote gateway/tunnel and registry release
remain unverified/not performed. Installed Telepty0.9.1 remains incompatible with
the three capability requirements. No live installation or service was changed.

This repository is the initial private source snapshot of a **work-in-progress candidate**. It is not a
release. `package.json` stays `"private": true`, nothing is published to npm, and pushing this snapshot
does not complete task 1215 or the actual remote-connection goal. Work is tracked under task 1215 for
the next aigentry release.

## What the snapshot contains
- Local transport: config gate, exact-target sends, owned inbox lifecycle, audit-verified replies,
  `request_id` dedupe, stdio MCP adapter (`bin/telesession-mcp.js`).
- Opt-in durable store (`TELESESSION_STATE_DIR`): request records, stored replies, inbox
  reattach/rotation, conservative restart recovery. Abrupt-crash unlock is not provided.
- Portable clean-environment MCP child launcher candidate (`bin/telesession-tunnel-child.js`).
- Unit/fixture tests, plus newly authored real-daemon restart regression tests
  (`test/real-daemon-restart.test.js` and additive helpers in `test/helpers.js`).

## Verification status
| Area | Status |
|---|---|
| Synthetic Linux VM run (fake telepty) | Historical: 22 isolation checks; 36 passed / 0 failed / 13 excluded. This was a fake-telepty suite. It is **not** evidence for an installed package or a live product, and the 13 excluded tests were not run. |
| Launcher unit tests (`test/tunnel-child.test.js`) | The original suite ran 12 passed / 6 cancelled in an independent run, a test-harness defect (the fake child turned an explicit `pid: undefined` into 4242). This snapshot carries the corrected fake. Hosted CI run 38112321584 (main `35196621`): passed on ubuntu, macos and windows. |
| Launcher independent suite (`test/tunnel-child-independent.test.js`) | 10/10 in an independent run; included in this snapshot. Hosted CI run 38112321584: passed on ubuntu, macos and windows. |
| Launcher independent pure verification and security triage | Ongoing at snapshot time. |
| Real-daemon restart regression tests (RC5, `test/real-daemon-restart.test.js`) | Authored and syntax-checked only. Never run. |
| Existing real-daemon tests (`transport-telepty.test.js`, `mcp.test.js`) | Not run against a candidate telepty daemon. |
| Snyk / security scan of the product candidate | **Pending (security owed).** Not run for this snapshot; not waived. |
| Real Dot roundtrip | NOTRUN |
| Tunnel launch (tunnel client + launcher) | NOTRUN |
| Real telepty daemon activation and restart | NOTRUN |
| Native macOS / Windows / Linux acceptance | NOTRUN |
| Hosted CI (`ci.yml`, explicit unit files, Node 20.20.0) | Run 38112321584 at main `35196621`: `npm ci` passed on all 3 OSes; unit passed on ubuntu and macos; pack dry-run passed. **Windows unit FAILED**: 101 tests, 63 pass, 10 fail, 28 skipped, 0 cancelled. All 10 failures are in `test/store.test.js` (9 fault-seam exact-path predicates, 1 SIGTERM graceful stop). A test-side fix is pending review and a hosted re-run; see `docs/ci.md`. Unit CI is not product acceptance. |

No test result in this table was produced by creating this snapshot. No tests, builds or installs were
run to create it.

## telepty prerequisite
telesession requires three opt-in telepty daemon capabilities in `GET /api/meta`:
`inject-exact-target`, `register-create-only`, `delete-owned-session`. The existing telepty 0.8.5
baseline lacks all three, so the stock npm telepty package does **not** connect successfully with this
candidate. A telepty build with the candidate daemon change is required and has not been released.

## Integration and testing prerequisites (before any acceptance claim)
1. A telepty tree whose daemon carries the three capabilities; for the real-daemon tests, point
   `TELESESSION_TEST_TELEPTY_DIR` at it (or place it as a sibling `../telepty`).
2. Installed dependencies for both projects (telesession: `@modelcontextprotocol/sdk`, `zod`; telepty:
   its own dependencies including the native `node-pty` for the target platform).
3. An isolated environment: temporary HOME, ephemeral loopback ports, no live daemon, no real credentials.
4. Corrected launcher test harness, then the launcher's independent verification steps in
   `docs/tunnel-child.md`.
5. A Snyk Code scan of the first-party JavaScript, with fixes and a rescan.
6. Only then: operator-approved live daemon activation, tunnel launch and a real Dot roundtrip whose
   reply is audit-verified as `trusted`.

## Safety limits
- Loopback-only telepty URL; token only from env or an absolute token file; never in tool args, results,
  logs or the state dir.
- The launcher filters the child env but is not an OS sandbox; the child runs as the same user.
- After an abrupt crash the durable store stays locked (`STORE_LOCKED`) until a reviewed repair exists.
- Replies can be lost while the inbox is down; loss is reported, never replayed. Never exactly-once.
- telesession never changes telepty's peer policy and never starts, stops or restarts daemons.
