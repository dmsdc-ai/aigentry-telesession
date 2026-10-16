# Changelog

## Unreleased

### Added

- Relayed-receipt binding, origin side (#2026101110 U1, #8, #7; spec `docs/specs/2026-10-12-relayed-receipt-binding.md`).
  Receipts are checked by record type. A local direct record keeps the 0.2.0 rule unchanged. A relayed or cross-host
  direct record ("path S") accepts only a v2 receipt from the final daemon. That receipt must be signed (Ed25519,
  verified with `node:crypto`; there is no signing code in `src/`) with a key pinned in the route resolver's new
  optional per-peer `receipt_keys`, under the origin's own name for the destination. It is then checked in the
  B0–B9 order: correlation, origin inject, key, signature, `session_guard`, final session, stage rules, and
  a once-only receipt identity. A refused receipt is counted with its code. It changes no state, sets no marker and
  is never evaluated as v1 or unproven. A relayed v1 receipt is now refused `SIGNATURE_REQUIRED` instead of
  `INJECT_MISMATCH`; the outcome (refused) is the same.
- The ledger record gains two optional fields, `origin_inject_id` and `applied_receipts` (bounded at 16; at the bound a
  new identity is refused with `RECEIPT_LIMIT` and nothing is evicted). `LEDGER_VERSION` stays `1`, so a 0.2.0 build
  still opens the ledger. A direct record now stays bound through `origin_inject_id` after the store purges its request.
- `telesession_request_status` gains an optional `receipt_refusals` field holding the refusals from the last receipt
  pull, omitted when there are none.
- Nothing changes in a live deployment by default. The default receipt adapter stays `NO_RECEIPTS` and no
  `receipt_keys` are pinned. Production completion needs telepty#100/#111/#113 and the operator approval in spec
  §2.5/§4.4. The tests run only against synthetic fixtures (`test/helpers/fake-receipts.js`, `fake-telepty.js`,
  `relay-context.js`).
- Relay intake on the relaying side (#2026101110 U4, #2, #8; spec §1.2, §7). The transport gains `relayIntake` (not an
  MCP tool). It parses the leg-1 wire header and looks up the origin inject I at its own daemon. The lookup is by
  arrival window (interim §1.2(b), the default) or by `correlation_id` with the stored leg-1 context (T-1 §1.2(a),
  `extensions.originLookup: "t1"`). Either way it keeps only rows whose verified sender is the reply-to inbox. Exactly
  one row gives a final `relay_context` (C and I copied verbatim, `hop` = inbound + 1). Anything else is
  `ORIGIN_INJECT_AMBIGUOUS`, recorded on the outbox item, and the work is still forwarded, without `relay_context`.
  Outbox items gain the optional fields `relay_context` and `origin_lookup` (`LEDGER_VERSION` stays `1`). The relay send
  puts `relay_context` into the inject body verbatim and refuses `hop > 4` before any inject with `RELAY_HOP_LIMIT`.
  Like `PEER_UNSUPPORTED`, that refusal is a definite non-send: the item is requeued, then `failed` at max_attempts.
  Cross-host relay sends stay fail-closed (U2).

### Fixed

- Relay sends to another host fail closed (#2026101110 U2). The transport injects only into its local telepty
  daemon, and telepty has no daemon-side forward to an exact remote session (telepty#111). Before this fix, a relay
  item routed to another peer was injected into the local session that had the same name. Such an item is now
  refused before any inject with `PEER_UNSUPPORTED` (`sent: "no"`, so the existing requeue and quarantine rules apply).
  The transport's default resolver now reports a non-local destination as `PEER_UNKNOWN` instead of
  `ROUTE_UNRESOLVED`. Local relay items and an origin `send` with a remote `destination` (the relayed model through
  the local leg-1 target) are unchanged.
- Snyk Code review of 1391aaf/904d7c8: the U1 test helper `daemonCall` (`test/relay-receipt-binding.test.js`) now
  refuses anything but the loopback fake daemon's origin and an `/api/` path. Test-only; no src change.

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

### Fixed

- Ledger capacity (#5): the 1024-record bound counts non-retired records only (retirement stays a marker;
  nothing is deleted), so a ledger whose records are all retired accepts new requests again. A full ledger
  now refuses the send before the inject with `LEDGER_FULL` (`accepted:false`), counted in the new
  `ledger.ledger_full` counter instead of `write_failed`. Retired records still count toward the 4 MiB
  byte bound (operator prune remains dry-run only).
- Ledger capacity, review 1 B1 (#5): the pre-send check could approve a send whose create was then refused
  (records past retention but not yet marked, near the byte bound: retiring them inside the create overflowed
  4 MiB), so the inject was accepted and left untracked on every send. The transport now reserves the record
  in the ledger before the inject (`reserve`/`release` replace `capacity`): due records are retired in their
  own commit, and the reservation holds one record and 8 KiB (was a 4 KiB margin, below a largest record) that
  no other commit may use, including the reconstruction of lost records. The size check uses the committed
  file size (no full `JSON.stringify` per send). Near the byte bound, other ledger writes may now return
  `LEDGER_FULL` while sends are in flight (8 KiB per send).
- Relay destination: the in-process relay passed only the session name to the transport send and dropped the
  host the route resolved. It now passes the route's peer as `destination`; a local route (the target itself)
  stays a direct send.
- Receipt binding (fail closed): `request_status` passes the injects this origin knows (its own inject and
  its relay receipts) to `applyReceipts`. A receipt naming another inject is refused (`INJECT_MISMATCH`), and
  with no known inject every receipt is refused (`INJECT_UNKNOWN`). An unproven receipt from another session
  sets no marker. `attested_by.host_label` is not compared (spec §9.1 binds the verified host and the attested
  session). Refusals are counted in the adapter result only.
- In 0.2.0, relayed receipts are refused by design (the origin cannot know the final inject) pending
  https://github.com/dmsdc-ai/aigentry-telesession/issues/8. The relay is opt-in and `NO_RECEIPTS` is the
  default, so nothing live changes.
- Unit runner list (#6): `test:unit` now names every test file that runs without a real daemon (16 files,
  was 4), including the fake-adapter full-route proof (`test:e2e` still runs it alone); `test:real-daemon`
  names the rest; a guard test fails on an unnamed test file.
- Snyk Code review of 8016f25: the inbox receiver is plain HTTP by design and binds `127.0.0.1` only; a new
  test proves it refuses connections on `::1`, `127.0.0.2` (Linux) and every non-loopback interface (it fails
  on a `0.0.0.0` or `::` bind). The daemon URL stays loopback-only by config. The test-only raw HTTP helper
  now refuses any non-loopback URL. No src change.

### Spec change (for the spec owner)

- `docs/specs/2026-10-11-e2e-delivery-protocol.md` §6.1 is rewritten in this release: retired records no
  longer count toward the 1024-record bound, and the transport reserves the record before the inject. PR #3's
  copy of the spec still has the old text ("retired records count toward the record and byte bounds").

### Compatibility

- The request header gains an additive `correlation=` field.
- Only a reply carrying the `[telesession ack=final]` token on one of its first three lines is the semantic ACK.
- After expiry, `read_reply` returns `ok:true` with no `inject_id`; `wait_ms` is ignored.
- Rollback hazard (#5): the ledger load check now bounds only the non-retired records, so this release can
  write a ledger with more than 1024 records in total (the extra ones retired). An earlier build opens such a
  ledger as `LEDGER_CORRUPT` (the ledger is then unavailable and sends go untracked). Before reverting, an
  operator must prune the retired records down to 1024 records in total. No on-disk format or version change.

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
