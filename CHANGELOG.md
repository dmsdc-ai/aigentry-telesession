# Changelog

## 0.2.0 — 2026-10-12

End-to-end delivery protocol (spec `docs/specs/2026-10-11-e2e-delivery-protocol.md`).

### Release integration (2026-10-31)

The 0.2.0 release line (`704200d`) now includes the reviewed Linux follow-up (`90d88aa..91b8c9b`).

- Inject uncertainty: an inject answered with HTTP 5xx, `delivery_uncertain: true` or code `DELIVERY_UNCERTAIN` is
  `accepted: "unknown"`, kept `uncertain` and never re-sent automatically. Registration and owned DELETE
  classification are unchanged.
- Audit recovery: a verified `failed:*` audit row (including `failed:DELIVERY_UNCERTAIN`) stays
  `uncertain`/`recovery: "unverified"`. It is no longer `refused`/`AUDIT_DELIVERY_FAILED`. Explicit `blocked:*`
  remains refused.
- Receipt: tracking state `aborted` alone is `unknown`, not `refused`.
- CLI: `telesession-mcp --help`/`-h`/`--version` answer before any config, store or MCP initialization. Any other
  argument is refused with `ARGS_UNEXPECTED` (exit 2).
- Package: `API-CONTRACT-TELESESSION.md` and `CHANGELOG.md` are packaged. Docs are an explicit user-facing
  allowlist; repository status/CI records and dated operational reports are not shipped. `private` was removed,
  and `publishConfig.access: "public"` added (publication is a separate, gated step). The dependency floors were
  raised to the tested lock versions, `@modelcontextprotocol/sdk ^1.29.0` and `zod ^3.25.76`. Lock resolutions
  are unchanged.
- License notice: the MIT `LICENSE` file (2026 dmsdc) is now included and packed. The license terms are
  unchanged. `test:pack` asserts the exact packed file set.
- Release validation: the new `compatibility.yml` workflow, called by `release-check.yml` when its optional
  `telepty_ref` input is set (`workflow_call`; direct dispatch only once the file is on the default branch), runs the
  full suite, `test:pack` and (Linux/macOS) installed-tarball acceptance against one exact Telepty commit (40-hex
  input) on ubuntu/macos/windows. The release gate fails unless that run passed on the requested SHA. It does not
  replace the cross-host Mac/Linux live communication gate required before Telepty publication.
- Tests: `test:pack` (packed file list, including all four bins) and `test:installed` (installed-artifact
  acceptance, 6 tools). The RC5 restart child is consumer-owned (`test-support/restart-credential-child-1215.cjs`).
  The new entrypoint and inject-uncertainty files are named in `test:unit`.
- Compatibility: requires Telepty 0.10.0 (the three capabilities plus a non-2xx `delivery_uncertain`/`DELIVERY_UNCERTAIN`
  answer and `failed:DELIVERY_UNCERTAIN` audit rows). It is not yet published, and no installed or runtime proof
  of this integrated candidate exists. A receiver 503 is dead-lettered by that Telepty as `unknown` without retry.
- Unsupported in 0.2.0: the relay runner, `telesession-relay-tick` and `telesession_send.destination`. Non-local
  routes are refused with `PEER_UNSUPPORTED`. The outbox is not wired, relayed receipts are refused (#8) and remote
  provenance is unavailable (telepty#100). A `destination` request stays `pending` and is never completed
  remote delivery.
- Known limitation (#10, open): a durable receiver rejection (4 candidates per request or 64 stored texts) answers
  503 and only increments `inbox_rejected`. There is no reason counter and the request is not marked, so with
  Telepty 0.10.0 such a reply is lost unless the replier resends. Minimum follow-up: per-reason counters
  (`candidates_full`, `store_full`) and request marking.
- The test counts under "Verified / not verified" below are historical (2026-10-12 release branch). The integrated
  candidate has not been tested yet.

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
- Relay sends to another host fail closed (#2026101110 U2, Mac re-review TS1). The transport injects only into its local telepty
  daemon, and telepty has no daemon-side forward to an exact remote session (telepty#111). Before this fix, a relay
  item routed to another peer was injected into the local session that had the same name. Such an item is now
  refused before any inject with `PEER_UNSUPPORTED` (`sent: "no"`, so the existing requeue and quarantine rules apply).
  The transport's default resolver now reports a non-local destination as `PEER_UNKNOWN` instead of
  `ROUTE_UNRESOLVED`. Local relay items and an origin `send` with a remote `destination` (the relayed model through
  the local leg-1 target) are unchanged.
- Relay claim (Mac re-review TS2): a tick claimed items from a snapshot taken before earlier awaited sends, so an
  item quarantined meanwhile (`payload_changed`, text dropped) or past its correlation deadline was still sent with
  the stale text, and a failed outbox sweep was ignored. The ledger now claims the current item in one commit
  (`outboxClaim`: queued, not quarantined, correlation live and before its deadline) and the send uses that
  item's payload; a refused claim is `skipped`. A failed sweep ends the tick with `RELAY_SWEEP_FAILED` before any
  send.
- Relay retry after a proven non-send (Mac re-review TS3): a connection refused at the inject requeued the item,
  but the next tick reused the request id, got the transport's stored refusal back and failed the item without a
  new POST. Each attempt after a proven non-send now uses its own request id (`relay:<key>:<attempt>`; attempt 0
  keeps `relay:<key>`). Intent, uncertain and sent items are still never sent again.
- Relay retry, round 2 review B-1: `REQUEST_IN_FLIGHT` (a send with the same request id still in flight) was
  treated as a proven non-send, so the next attempt's new request id escaped the same-id dedupe and the text was
  delivered twice. It is now `sent: "unknown"`: the item goes `uncertain` and is never sent again.

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
