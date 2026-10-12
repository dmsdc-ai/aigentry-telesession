# Changelog

## 0.2.0 — 2026-10-12

End-to-end delivery protocol (spec `docs/specs/2026-10-11-e2e-delivery-protocol.md`).

### Added

- Public `request_id` per request and an immutable, origin-minted `correlation_id` set at request creation.
- Durable correlation ledger with a request state machine.
- `telesession_request_status` MCP tool (and `transport.requestStatus`).
- Ledger-backed addenda and a `read_reply` cursor (`replies` + `next_cursor`).
- Post-expiry lookup by nonce, `request_id` or `correlation_id`; `read_reply` answers from the ledger after expiry.
- Retention lifecycle with outbox quarantine markers, and `telesession-ledger-prune --dry-run`, which opens the
  ledger read-only and lists what would be pruned.
- Provenance/receipt adapters with fail-closed defaults.
- Opt-in in-process relay runner, `TELESESSION_RELAY_INTERVAL_MS` (default off), and a one-shot
  `telesession-relay-tick` CLI that refuses to run while the live lock is held.

### Compatibility

- The request header gains an additive `correlation=` field.
- Only a reply carrying the `[telesession ack=final]` token on one of its first three lines is the semantic ACK.
- After expiry, `read_reply` returns `ok:true` with no `inject_id`; `wait_ms` is ignored.

### Verified / not verified in this release

Measured on the release branch, Linux, Node 20.20.0, 2026-10-12:

- `node --test test/`: 255 tests, 251 pass, 1 fail, 3 skipped. The failure is RC5, which refuses to skip
  when no telepty fixture tree is configured.
- `TELESESSION_TEST_TELEPTY_DIR=<candidate telepty tree> node --test test/real-daemon*.test.js`: RC5 1 test,
  0 pass, 1 fail (timed out at the child-reply step; telepty#107).
- Real-daemon describes with the same tree (`test/transport-telepty.test.js`, `test/mcp.test.js`): transport 9/9
  pass, MCP 1/1 pass.

Not verified:

- Linux only; macOS and Windows NOT verified.
- Remote provenance/receipt remain fail-closed (`REMOTE_PROVENANCE_UNAVAILABLE`) until telepty#100 and the
  Mac-side receipt work land.
- No unattended cross-host E2E was executed.
- The real-daemon CI gate is not included; the workflow is held in PR #3.
- The relay runner is not activated anywhere.
- RC5 (telepty#107) status: passes against telepty with PR #108 (`5b3619e`, per-session submit barrier) —
  real-daemon set 28/28 pass, RC5 alone 3/3 consecutive passes (2026-10-12); fails on `e86f414` and `v0.8.5`
  (27/28; a pre-existing telepty defect, not a regression in this release). The release requires a telepty
  build containing #108; the pinned ref moves to the tag that carries it once released.
