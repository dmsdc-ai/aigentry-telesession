# SPEC — telesession end-to-end delivery protocol (task #2026101110)

Status: draft for review. Phase 1 (spec) of a spec-first delivery; Phase 2 implements the slice in §13.
Measured basis: source of this repository at `90d88aa` (read 2026-10-11). Nothing here was measured
against a live daemon or a remote host. De-identified: no hostnames, addresses, session ids or tokens.

## 1. Problem and goal

A turn-based, listener-less agent (the *origin agent*) asks, through the telesession MCP tools, for work
to be done by a session that may be one or more hops away. Today the answer can only be read with
`telesession_read_reply`, and exactly one verified reply per nonce is kept: a second verified reply for
an answered nonce is quarantined as `duplicate` and dropped (`classifyAuditRows`: `issued.answered`;
`accept()`: `rec.state === "answered"` → `bump(…, "duplicate")`). When a relaying session sends a
"no ACK within the window" reply first and the real ACK later, the late ACK has nowhere to land.

Goal (user directive): when the origin agent asks for an acknowledgement, the acknowledgement must reach
it without human relay and without extra follow-up queries beyond its normal poll. Each host solves its
own side; this spec covers the telesession (origin endpoint) side and the adapter boundary to telepty.

## 2. Scope / non-goals

In scope: correlation records with explicit stages; addendum replies per nonce with a monotonic sequence
and a cursor; a `telesession_request_status` read path; a durable correlation ledger + outbox with
restart recovery and dedupe; a relay tick library (claim → intent → send → receipt → uncertain) with an
injected send primitive; a route-resolution interface; the guarantee model.

Non-goals: telepty changes (alias resolution #105, host provenance #100, consumption receipts
#103/#104, see §9); starting any process, timer or unit (§10 activation gate); a push/wake into the
origin agent (it has no listener — §8 documents the poll path); exactly-once side effects for arbitrary
CLI work (never claimed); a direct origin-agent → remote-host route (UNSUPPORTED here: the tunnel
terminates on one endpoint host only).

## 3. Endpoint and hop model

| term | meaning |
|---|---|
| endpoint | `{host, session}`: logical host id (canonical peer id, §9) + exact session id |
| origin endpoint | where the request was created and where the final ACK must be recorded (telesession on the tunnel host) |
| destination endpoint | the session that must process the request; it alone may produce the semantic ACK |
| hop | any session/daemon in between (local daemon queue, a relaying orchestrator, a bridge) |
| leg | one origin→destination pair with its own record; a relaying session that forwards work opens a new leg whose origin is itself |
| route | the request path (hops) — recorded, not assumed to be the reply path |
| `correlation_id` | 32 hex minted once at request creation by the origin; immutable; carried on the wire header and accepted on events/receipts (§4.1). `nonce` stays the per-leg reply key and `request_id` the caller's idempotency key; neither is ever overwritten |
| return route | `reply_to` endpoint (+ resolver locator) fixed at creation; immutable |

Rules: (R1) an intermediary hop ACK can advance only `transport_accepted`/`durable_received` of the
leg it served, never `processing_completed`/`origin_ack_received`. (R2) the reply path need not equal the
request path; the return endpoint is resolved through the resolver (§9), never derived from the inbound
hop. (R3) a marker string (e.g. "FROM <host>") or a content-hash match is corroboration, never sender
authentication; authentication is the adapter's verified-sender attestation (today: telepty audit
`verified_sender_sid` + epoch for the local host only).

Topology in this environment: origin agent → MCP tunnel → telesession (origin endpoint) → local daemon →
orchestrator session (destination of leg 1) → … (legs 2..n opened by the orchestrator). The ACK of
leg n reaches the origin agent as an addendum reply of leg 1 relayed by the leg-1 destination; the
origin agent never needs to poll leg n directly.

## 4. Record schemas

### 4.1 Ledger request record (`ledger.json` → `records[<nonce>]`)
| field | type | notes |
|---|---|---|
| `nonce` | 32 hex | per-leg reply key (`REPLY <nonce>`); immutable; also the reply-file key |
| `correlation_id` | 32 hex\|null | minted at creation (origin), immutable; on the wire as `[telesession nonce=<n> reply-to=<inbox> correlation=<id>]`; returned by `telesession_send` and the status view; null only for records written before the field existed |
| `request_id` | string\|null | caller idempotency key (`^[A-Za-z0-9._:-]{1,128}$`) |
| `origin` | endpoint | immutable |
| `destination` | endpoint | immutable; only it may produce destination stages |
| `via` | endpoint\|null | leg-1 destination when the final destination is further away (relayed request); immutable |
| `via_generation` | string\|null | leg-1 destination epoch (used to verify relayed replies) |
| `reply_to` | endpoint | immutable return route |
| `generation` | string\|null | destination epoch/credential generation expected; null = unknown → destination events stay unauthenticated-for-stage (counted, not applied) |
| `payload_sha256` | 64 hex | hash of the exact bytes sent; immutable |
| `stage` | enum §5 | highest stage reached (monotonic) |
| `stages` | map stage→ISO\|null | first-evidence time per stage; null = no evidence |
| `terminal` | null \| `{state:"rejected", at, reason}` | only an authenticated destination refusal sets it |
| `created_at`, `deadline_at`, `retain_until` | ISO | `deadline_at` ends the *observation window*, not the record |
| `replies` | list of reply index entries (§4.3) | ordered by `seq` |
| `next_seq` | int ≥ 1 | monotonic, never reused |
| `checkpoint` | null \| `{cursor, at}` | the origin agent's acknowledged read position |
| `ack_seq` | int\|null | seq of the final reply (`[telesession ack=final]`, §5) that recorded `processing_completed`; only moves forward |
| `unproven` | map stage→reason | destination stages seen but not authenticatable, e.g. `REMOTE_PROVENANCE_UNAVAILABLE` |
| `late_pending` | list `{sha256, received_at}` (bounded 4) | reply bytes held after the transport TTL, awaiting verification |
| `events` | list of applied dedupe keys (bounded 64) | event dedupe |
| `rejected` | map reason→count | refused events (wrong hash / generation / host / unauthenticated / hop-final) |

### 4.2 Event (input to `recordEvent`)
`{nonce, stage, payload_sha256, generation, from: endpoint, authenticated: boolean, hop: "destination"|"intermediary", provenance_unavailable?: boolean, reply_seq?, reply_sha256?, correlation_id?, reason?}`.
`stage` ∈ `transport_accepted, durable_received, agent_consumed, processing_completed, rejected`.

### 4.3 Reply / addendum (index entry in the record; text in a reply file)
| field | notes |
|---|---|
| `seq` | 1,2,3… per nonce; seq 1 is the *initial* reply, seq ≥ 2 are *addenda* |
| `sha256` | sha256 of the reply text; file `replies/<nonce>-<sha256>.json` (existing naming; several per nonce) |
| `from` | endpoint of the verified sender |
| `verified` | adapter attestation; unverified replies are never stored as text |
| `attestation` | `destination` (verified from the destination itself) \| `relayed_by_leg1_destination` (verified from `via`; the remote destination stage stays unproven) \| `intermediary` |
| `late_after_ttl` | true when verified after the transport's nonce TTL (§8) |
| `received_at` | ISO |
| `dedupe_key` | `<nonce>:<sha256>:<from canonical>` |

Ordering is `seq` (assigned at commit time, under the single-writer lock), not file mtime or name.

### 4.4 Status view (`telesession_request_status` result)
`{ok, nonce, correlation_id, request_id, status, status_reasons, replies, next_cursor, ledger:{mode, write_failed, late_dropped}, stage, stages, unproven, deadline_passed, reply_count, late_after_ttl_count, cursor, ack_seq, final_ack_seq, delivered_to_origin_agent, checkpoint, outbox, rejected, completion_fact:null}`;
`status` ∈ `pending | completed | rejected | unknown | expired | not_tracked`.
`final_ack_seq` = seq of the final reply (same value as `ack_seq`, which is kept as an alias).
`delivered_to_origin_agent` = `checkpoint !== null && checkpoint.cursor >= ack_seq` (false while `ack_seq` is null).
`status_reasons` lists explicit codes such as `REMOTE_PROVENANCE_UNAVAILABLE`, `DEADLINE_PASSED`, `OUTBOX_UNCERTAIN`, `AWAITING_ORIGIN_AGENT_READ`.

## 5. State machine

Stages (ordered): `transport_accepted(1) → durable_received(2) → agent_consumed(3) → processing_completed(4) → origin_ack_received(5)`; terminal `rejected`; derived `unknown`, `expired`.

Allowed transitions / effects:
- An event for stage k sets `stages[k]` if null and `stage = max(stage, k)`. Out-of-order evidence is
  kept: skipped lower stages stay null (= no evidence, reported as `unknown` for that stage).
- A regressing event (k < stage) only fills a null timestamp; the stage never moves back.
- `processing_completed` recorded at the origin also sets `origin_ack_received` (the origin has now
  received and durably recorded the authenticated final ACK) and `ack_seq`. Nothing else sets it.
- Final vs interim reply: a verified destination reply is the semantic ACK (`processing_completed`) ONLY
  if its text contains the token `[telesession ack=final]` on one of its first three lines. Any other
  verified reply is stored as an addendum with NO stage effect. Authentication is unchanged (verified
  sender); the token only classifies which verified reply is final and never authenticates. A later final
  reply is a new event (its sha256 is part of the event key) and moves `ack_seq` forward; `ack_seq` never
  moves back.
- Status `completed` requires `origin_ack_received` AND `delivered_to_origin_agent`; with the ACK
  recorded but not yet read by the origin agent the status is `pending` (`AWAITING_ORIGIN_AGENT_READ`).
- A destination-stage event that cannot be authenticated because remote host provenance is unavailable
  (telepty #100; event `provenance_unavailable:true`) is not applied: `unproven[stage] =
  REMOTE_PROVENANCE_UNAVAILABLE` and the status carries that reason code.
- `rejected`: only by an authenticated destination event; terminal for stages; later replies are still
  stored as addenda (they are data).
- Derived `unknown`: (a) `deadline_at` passed without `origin_ack_received`; (b) the outbox shows
  `uncertain`; (c) the record has no evidence beyond `transport_accepted` and the transport could not
  observe more. A timeout NEVER yields `not_delivered`.
- Derived `expired`: tracking ended (record retired after `retain_until`, or nonce in the retired list).
  It means "outcome unknown, no longer tracked", not "not delivered".

Event validation, in order, with no state change on failure (counted in `rejected[reason]`):
unknown nonce → `UNKNOWN_CORRELATION`; a `correlation_id` present and ≠ record → `CORRELATION_MISMATCH`
(not counted, no state change; also checked on reply receipts, `appendReply`); `payload_sha256` ≠ record → `HASH_MISMATCH`;
`authenticated !== true` → `UNAUTHENTICATED`; destination stages (3, 4, rejected) from a non-destination
endpoint or with `hop:"intermediary"` → `SOURCE_MISMATCH` / `HOP_NOT_FINAL`; `generation` ≠ record
generation (or record generation null for a destination stage) → `GENERATION_MISMATCH`.
Endpoint comparison uses canonical peer ids from the resolver (§9), so two locator forms of the same
peer compare equal and an unknown form is a mismatch.

## 6. Storage layout and atomicity

```
<ledger dir>/            0700
  lock                   O_EXCL single writer (same strict rule as the store: never reclaimed)
  ledger.json            {schema:"telesession-ledger", version:1, generation, records:{}, outbox:{}, retired:[]}
  replies/<nonce>-<sha256>.json   {v:1, nonce, sha256, received_at, text}
```
Every write: tmp (O_EXCL, 0600) → write → fsync → close → rename → dir fsync (store convention).
Reply text file is written and fsynced BEFORE the commit that references it (a crash leaves at most an
unreferenced file, swept on open). Bounds: records 1024, replies per nonce 32, outbox 256, ledger file
4 MiB, reply text 64 KiB, events per record 64, retired 256. Restart: reload `ledger.json`, validate,
re-enter idempotently (§7, §10). The ledger never stores the origin prompt text, tokens or bearer values; an outbox item keeps its relay
payload only until its receipt is recorded.

Lock holder: the lock file records the holder pid. If it exists and that pid is not alive (`ESRCH`),
open fails with `LEDGER_LOCK_STALE`; a live, unreadable or unparseable holder is `LEDGER_LOCKED`. The lock
is never reclaimed automatically (pid reuse). Operator recovery: confirm that no telesession process uses
the state dir, then remove `<ledger dir>/lock`. The transport keeps an open failure's code: while the ledger
is unavailable, `telesession_request_status` returns `LEDGER_UNAVAILABLE` with `ledger_code` and
`telesession_health` reports `ledger: {state:"unavailable", code:"LEDGER_UNAVAILABLE", ledger_code}`
(`LEDGER_NOT_CONFIGURED` only when no ledger was configured).

Read-only / permission-limited directory: open does not crash. If the lock cannot be created
(`EACCES`/`EROFS`/`EPERM`) and `ledger.json` is readable, the ledger opens `read_only`: reads work,
every mutation returns `{ok:false, code:"LEDGER_READ_ONLY"}`. Otherwise `LedgerError` with a code.

## 7. Dedupe keys and idempotency

| object | key | duplicate effect |
|---|---|---|
| request | `nonce` (+ `request_id` → existing record, existing transport rule) | returns the existing record |
| event | `<nonce>:<payload_sha256>:<hop canonical>:<stage>` (+ `:<reply sha256>` for `processing_completed` from a final reply) | no-op, `deduplicated:true` |
| reply | `<nonce>:<reply sha256>:<from canonical>` | no-op, same `seq` returned |
| outbox item | `<nonce>:<payload_sha256>:<to canonical>:<kind>` | enqueued once; never re-sent after a receipt |

Duplicate *messages* are collapsed by these keys. Duplicate *side effects* at the destination (the
work itself) cannot be prevented by telesession: delivery is at-least-once, and a destination must
treat `nonce` as its own idempotency key. Exactly-once is never claimed.

## 8. Addendum + request-status read path (MCP, backward compatible)

`telesession_read_reply` input gains optional `cursor` (int ≥ 0). Output keeps every existing field
(`reply:"trusted"`, `text`, `inject_id`, `verified_sender`, `received_at` = the first reply, seq 1) and
adds `replies: [{seq, text, sha256, from, received_at}]` (seq > cursor, ordered) and `next_cursor`.
Callers that ignore the new fields see exactly the old behaviour.

New tool `telesession_request_status` — input `{nonce, cursor?}` (strict); read-only except that a
`cursor` argument records the caller's checkpoint (`checkpoint = max(old, cursor)`): the origin
agent's final receipt. Output: §4.4.

Poll/resume path and limits (no push exists): the origin agent polls `telesession_request_status`
(or `read_reply` with its last `next_cursor`) at its own turns. A stored reply is NOT a wake of the
parent turn; nothing interrupts the agent. Requests with an initial reply stay listed until
`checkpoint ≥ last seq` AND `origin_ack_received` or `rejected`; until then status is `pending`/`unknown`,
so they are never forgotten. Late replies: a verified reply is never dropped because the transport's 15-min nonce TTL passed.
For ledger-backed nonces the receiver holds the bytes (`late_pending`), verifies them against the
telepty audit with the ledger record's destination + generation (window up to `retain_until`) and stores
them as an addendum with `late_after_ttl: true`, counted in status (`late_after_ttl_count`). The ledger
write comes before the audit `inject_id` is bound, so a transient ledger failure leaves the bytes pending
and the next pass verifies them again (never `duplicate`). Unverified late bytes are dropped and counted. The transport's own expiry semantics stay unchanged (OQ-1).

## 9. Route resolution and the telepty dependency boundary

Interface (`src/relay/route.js`):
```
createRouteResolver(peers: [{peer_id, locators: string[]}]) →
  canonical(hostForm) → peer_id | null
  resolve({host, session}) → {ok:true, peer_id, locator, session} | {ok:false, code:"ROUTE_UNRESOLVED"|"ROUTE_AMBIGUOUS"}
  sameEndpoint(a, b) → boolean   (canonical host equal AND exact session equal)
```
The peer table is the permitted peer graph supplied by the operator/telepty; the resolver never
guesses (no DNS, no fuzzy match). A locator form that maps to two peers is `ROUTE_AMBIGUOUS`.

Telepty dependencies (not implemented here):
| issue | needed for | until fixed |
|---|---|---|
| #105 alias forms differ per node | one canonical peer id per host across nodes | the resolver table must list every form; unlisted form → unresolved |
| #100 inbound peer injects not host-attributed | `authenticated` for remote-host events | remote events are corroboration only → no remote destination stage is applied |
| #103 / #104 "submitted" = queue receipt | `agent_consumed` from a consumption observation | queue receipt maps only to `transport_accepted` |
| #102 (diagnostics) | separate queue vs parked backlog | §11 reads them separately when present, else `unknown` |

## 10. Relay tick (library + CLI entry; activation gated)

Pure functions over the ledger with an injected `send(item) → {ok, transport_id} | {ok:false, sent:"no"|"yes"|"unknown", code}`:
1. CLAIM+INTENT: `queued → intent` committed (fsync) BEFORE send; the ledger lock is the claim.
2. SEND: call the injected primitive once.
3. RECEIPT: `ok` → `sent` with `{transport_id, at}`; `sent:"no"` → back to `queued`, `attempts+1` (bounded
   3, then `failed`); `sent:"yes"` refusal → `failed` with code; `sent:"unknown"` → `uncertain`.
4. UNCERTAIN: on open, any `intent` without receipt (crash between 1 and 3) → `uncertain`. Never resent
   automatically; surfaced for operator review.
5. DEDUP: an item with a receipt is never relayed again; a changed payload is a new key.
`sent` is hop evidence (`transport_accepted` of that leg) only.

Activation gate: the library and a one-shot CLI entry may exist; running it as a process, timer or
unit is a **separate approval**. This slice adds no loop, timer or unit.

## 11. Diagnostics linkage

Reading telepty state must report, separately: daemon queue depth vs bridge parked backlog;
heartbeat-ok vs data-path-ok; `lastActivity` vs `lastOutput`. Missing evidence → `unknown`.
Stale parked directives are never flushed/replayed unconditionally: items older than the record
deadline or without a matching live correlation go to a quarantine list for review. Any step that
deletes data or restarts a live service is a **separate approval**.

## 12. Guarantee model

- No unconditional ACK guarantee under permanent disconnect or a non-responding destination.
- Eventual delivery assumes: the origin ledger survives (durable disk), the outbox is retried while
  `sent:"no"` is certain, the destination eventually runs and replies, and the reply route resolves.
- States for non-success: `pending` (within deadline), `unknown` (deadline passed / uncertain /
  insufficient evidence), `rejected` (authenticated refusal), `expired` (tracking ended), `failed`
  outbox item (definite refusal or retries exhausted). Cancel = operator action, separate approval.
- Success only when the origin ledger records an authenticated destination `processing_completed`
  (→ `origin_ack_received`). Integrity (hash), sender authentication (adapter attestation),
  correlation (`correlation_id`, nonce + generation) and delivery stage are verified and reported separately.
- Multi-leg routes (review N12): a relaying leg-1 destination may carry the origin's `correlation_id` into
  the legs it opens; the origin ledger does not yet link a leg-n nonce to the leg-1 nonce.

## 13. Phase-2 implementation slice

(a) `src/relay/ledger.js` — records, stages, validation, atomic writes, restart, read-only open.
(b) addenda: transport keeps verified replies after the first as ordered addenda in the ledger;
`read_reply` returns `replies` + `next_cursor`.
(c) `telesession_request_status` tool (MCP) + `transport.requestStatus`; `telesession_send` gains an
optional `destination {host, session}` for a relayed final destination (the target becomes `via`).
(d) `src/relay/relay.js` — outbox tick with injected send; `src/relay/route.js` — resolver.
The transport uses the ledger only when one is passed in (opt-in third argument); the MCP bin opens
it at `<stateDir>/ledger` when a state dir is configured (no new env var).

## 14. Test matrix (new files under `test/`)

| # | case | expected |
|---|---|---|
| T1 | late ACK after a terminal (initial) reply | stored as addendum seq 2; stage → `origin_ack_received` |
| G1 | interim reply, then final reply (transport) | interim: `pending`; final: `origin_ack_received`, `ack_seq` = final seq; `completed` after checkpoint |
| T2 | duplicate ACK, same content twice | one reply, one seq; second call `deduplicated` |
| T3 | out-of-order ACKs (completed before consumed) | stage 5; consumed timestamp filled later; no regression |
| T4 | restart: reopen ledger mid-flow | records/seq/cursor identical; next seq continues |
| T5 | crash between intent and receipt | reopen → `uncertain`; tick does not call send |
| T6 | wrong hash / wrong generation / wrong host / unauthenticated / intermediary-final | rejected with reason, no state change |
| T7 | deadline passed without ACK | status `unknown`, never `not_delivered` |
| T11 | verified reply after the transport TTL | stored as addendum `late_after_ttl:true`; status counts it |
| T12 | remote destination stage without provenance | `REMOTE_PROVENANCE_UNAVAILABLE`; addendum `relayed_by_leg1_destination` |
| T13 | ACK recorded, not yet read by the origin agent | `pending`; `completed` only after checkpoint ≥ `ack_seq` |
| T8 | route resolution with two locator forms of one peer | same canonical peer; unknown form unresolved |
| T9 | read-only ledger directory | no crash; reads work; writes `LEDGER_READ_ONLY` |
| T10 | MCP: six strict tools; `request_status` schema | existing refusals unchanged |

## 15. Supported OS scope

Linux: verified by this slice's tests (`node --test test/`). macOS/Windows: unverified — the ledger
reuses the store's POSIX permission model (0700/0600, uid check skipped on win32) and the read-only test
is POSIX-only (skipped when running as root or on win32).

## 16. Open questions

- OQ-1: whether the transport's own nonce TTL/expiry semantics should change for ledger-backed nonces
  (late replies are already kept via §8 `late_after_ttl`; this is about `read_reply` NONCE_EXPIRED).
- OQ-2: multi-leg e2e ACK attestation across hosts needs telepty #100 host provenance; until then a
  remote ACK reaches the origin only as a verified addendum *from the leg-1 destination*
  (`attestation: relayed_by_leg1_destination`) and the remote stage reads `REMOTE_PROVENANCE_UNAVAILABLE`.
- OQ-3: whether `agent_consumed` should be fed from telepty consumption observations (#103/#104) in
  `requestStatus` (extra daemon read per status call).
- OQ-4: outbox CLI entry naming and the operator review UX for `uncertain` items.
