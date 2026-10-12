# SPEC — relayed-receipt binding protocol (task #2026101110, plan unit U1; issues #8, #7, #2)

Status: draft for review. Companion to `2026-10-11-e2e-delivery-protocol.md` (the "base spec"); its §9.1
points here. Nothing in the base spec is changed except that pointer: the direct-record rule of `8016f25`
stays as it is (§1.3).
Measured basis: this repository at `8016f25` (release/0.2.0 candidate) and telepty at `db2f532` (wt-107),
both read from source on 2026-10-13. Nothing was measured against a live daemon, a second host or a real
key. De-identified: no hostnames, addresses, session ids or tokens.

Requirement this closes (user, binding): if the origin agent sent a request to a remote host, directly or
through a relaying hop, an ACK must eventually come back from that host to the origin's correlation
without any human step. 0.2.0 refuses every relayed receipt (`INJECT_MISMATCH`). The receipt names the
FINAL daemon's inject, and the origin only knows its own leg-1 inject. Nothing in base §9.1 links the two.

Terms: **O** = origin telesession and the daemon it injects into. **R** = a relaying hop (leg-1
destination session, its telesession process, its relay runner, its daemon). There can be several Rs.
**F** = the final daemon, the telepty daemon on the destination host that delivers to the destination
session. **D** = the destination session. **I** = origin inject id, **C** = `correlation_id`, **J** =
final inject id.

---

## 1. Origin correlation

### 1.1 `origin_inject_id`

`origin_inject_id` (I) = the inject id that the delivering daemon minted for the origin's leg-1 send and
returned to O in the send response (`telesession_send` → `inject_id`; minted at telepty `daemon.js:4758`).
Format `^[A-Za-z0-9._:-]{1,128}$` (same as `adapters.js:24`).
- Same-host leg 1 (this environment's topology, base §3): I is today's `s.inject_id`. The relayer's
  daemon is the daemon that minted it.
- Cross-host leg 1 (U2): I must be the id minted by the daemon that delivers to R. There is no
  daemon-side cross-host inject today (§1.4). The SSH arm returns only `{success:true}`
  (`cross-machine.js:329-348`). So I is known only when the hop returns the remote daemon's inject
  response: the HTTP arm (H-b) or telepty#111 (H-c). Otherwise a cross-host leg-1 record has I = null, and
  its receipts are refused `INJECT_UNKNOWN`. That fails closed and matches today's behaviour.

O persists I in the **ledger record** (new optional field `origin_inject_id`, §4.2), set in
`openLedgerRecord` from `b.inject_id`. Today `pullReceipts` reads the inject from the **store**
(`telepty.js:1416-1418`). The store purges a request after TTL + 1 day (`store.js:23`,
`telepty.js:1226`), while the ledger keeps it for 7 days (`ledger.js:23`). So between day 1 and day 7, even
a direct receipt is refused `INJECT_UNKNOWN` today. Persisting I in the ledger closes that gap too
(measured from source, not from a run).

### 1.2 Relay context: how I and C travel through every hop

Every relayed leg carries a **relay context**:

```
relay_context = { v: 1, correlation_id: C, origin_inject_id: I, origin_host: <O canonical peer id>,
                  final: { host: <F canonical peer id>, session: <D sid> }, hop: <int 1..4> }
```

- **O → R (leg 1).** C is already on the wire header (`[telesession nonce=… reply-to=… correlation=C]`,
  `telepty.js:1220`). I cannot be on the wire because the daemon mints it after the bytes are built.
  R obtains I from **its own daemon** by one of these two paths:
  (a) **telepty#100 T-1 (target):** the inject body gains optional `relay_context`. O passes
  `{v:1, correlation_id:C}` on leg 1. The delivering daemon stores it on the audit row and the
  tracked-inject record. R reads `GET /api/injects?to=<R>&correlation_id=C` and gets exactly one row,
  whose `inject_id` is I.
  (b) **Interim, no telepty change:** R's telesession reads `GET /api/injects?to=<R>&from=<reply-to inbox>`
  (filters exist: `daemon.js:3767-3779`) inside the record window. It accepts I only if exactly one row
  remains. Otherwise I = null (`ORIGIN_INJECT_AMBIGUOUS`, counted in R's outbox item), and the relayed
  receipt is later refused at O (`INJECT_UNKNOWN`).
  A wrong I cannot complete the wrong request: the binding (§1.3) needs I **and** C to match the **same**
  O record. A lookup error therefore yields a refusal, never a false completion.
- **R → next hop / F.** R's relay send, in whichever hop mode of §1.4, passes `relay_context` in the
  inject body that reaches F's inject route (telepty#100 T-2), with `hop + 1`. R copies `correlation_id`, `origin_inject_id`, `origin_host` and `final` **verbatim** from
  its inbound context. These fields are immutable along the route. `hop > 4` is refused by R
  (`RELAY_HOP_LIMIT`, outbox `failed`). The relay envelope text stays the work payload. The relay context
  is out-of-band (in the body, not in the prompt), so D's agent never needs to parse or echo it.
- **F.** The daemon whose canonical peer id equals `relay_context.final.host` mints J at its inject route
  (as at `daemon.js:4758`). It stores `relay_context` on J's tracked-inject record immutably, next to
  `session_id` and `session_epoch` (as at `daemon.js:679`). It echoes that context in every receipt for J
  (§2). D cannot change it: D only posts stage facts with its own bearer.

### 1.3 What the final receipt echoes, and the binding rule at O

A **relayed receipt** (receipt schema v2, §2.2) carries:
`origin_inject_id`, `correlation_id`, `origin_host`, `final_inject_id` (J), `final_host`,
`final_session`, `final_session_epoch`, `stage`, `seq`, `at`, `attested_by {sid, epoch, generation}`,
`key_id`, `sig`.

**Binding rule (fail-closed, evaluated in this order, the first failing check refuses).** For an O record
`rec` with `rec.via !== null` (relayed):

| # | check | refusal code |
|---|---|---|
| B0 | receipt well-formed (v2 shape, bounded fields) | `INVALID_RECEIPT` |
| B1 | `correlation_id === rec.correlation_id` | `CORRELATION_MISMATCH` |
| B2 | `role === "final"` / `auth_basis === "own_bearer"` (unchanged) | `HOP_FACT_ONLY` / `NOT_OWN_BEARER` |
| B3 | `rec.origin_inject_id` is a string (O knows its leg-1 inject) | `INJECT_UNKNOWN` |
| B4 | `receipt.origin_inject_id === rec.origin_inject_id` | `INJECT_MISMATCH` |
| B5 | `receipt.origin_host` canonicalises to O's own peer id | `ORIGIN_MISMATCH` |
| B6 | signature verifies under a key pinned for `canonical(receipt.final_host)` (§2.4) | `SIGNATURE_INVALID` / `KEY_UNKNOWN` |
| B7 | `sameEndpoint({host: final_host, session: final_session}, rec.destination)` and `attested_by.sid === final_session` and `attested_by.epoch === final_session_epoch` | `SOURCE_MISMATCH` |
| B8 | record not terminal, not retired; stage rules of base §5 (`GENERATION_MISMATCH`, `REJECT_AFTER_ACK`, …) via `ledger.recordEvent` | the ledger's code; terminal → `STALE_AFTER_TERMINAL` |
| B9 | receipt identity `(final_host, J, stage)` not already applied (§3, I-5) | not a refusal: `deduplicated` |

Accepted iff B0–B8 pass. On acceptance the receipt is applied as a **proven** destination event (base
§9.1: `processing_completed` → verified reply entry → `origin_ack_received` → `completed` after the
checkpoint). There is no "unproven" path for a relayed v2 receipt. A receipt that fails B6 is not
evidence and sets no `REMOTE_PROVENANCE_UNAVAILABLE` marker. The existing marker path (transport's
relayed final-reply via the leg-1 target, base §9.1) stays as it is.

**Counting.** Refusals are counted per pull in the `applyReceipts` result (`refused[code]`, as today).
They are also exposed in the status view as the optional `receipt_refusals` (last pull only, so repeated
polls do not inflate counts, §4.1). The 19:27Z decision (no health counter) stands.

**Direct records (`rec.via === null`): unchanged from `8016f25`.** They keep the known-inject set
(`adapters.js:76-77`; the set is now `{rec.origin_inject_id ?? store inject_id} ∪ outbox transport_ids`),
the provenance-adapter host proof and the ledger source check. A direct record never accepts a v2
receipt's `origin_inject_id` as a substitute for its own inject. A receipt **without** `origin_inject_id`
(v1) keeps today's behaviour exactly: direct → bound by the known-inject set; relayed → refused
(`INJECT_MISMATCH` when O knows an inject, `INJECT_UNKNOWN` when it does not).

### 1.4 Hop model: who performs the cross-host hop (today vs planned)

Measured in telepty `db2f532`. Most of it was measured by the U2 coder and relayed in the orchestrator
note; this author re-read the inject route only.
- `POST /api/sessions/:id/inject` resolves the **local** session table only (`daemon.js:4742-4746`:
  `exact_target` → own-property match → 404 for `sid@host`; otherwise a local alias).
- The bus auto-route strips `@host` and delivers locally (around `daemon.js:3430` and `:5433`).
- `GET /api/sessions` is local only.
- `sid@host` routing is **client-side, in the CLI** (`cli.js` around 3483-3548). It has two arms:
  - **SSH arm:** runs `telepty inject` on the peer and returns `{success:true}`. There is no inject id and
    no receipt (`cross-machine.js:329-347`).
  - **HTTP arm:** posts directly to the **remote** daemon's inject route with that peer's token from
    `~/.telepty/peers.json` (`cross-machine.js:443-509`).

So **no daemon and no telesession performs a cross-host hop today**. The hop is performed by a **session**
on the leg-1 host (the relaying agent R) through the CLI. Hop modes:

| mode | performed by | J known to R | relay_context reaches F | what it cannot prove |
|---|---|---|---|---|
| **H-a** SSH arm (today) | R's agent via CLI | no | no (the CLI has no such option) | the existence, identity and session of the final inject. F cannot echo I/C, so no v2 receipt can exist. The record stays pending → unknown; a completion reaches O only as the leg-1 addendum (`relayed_by_leg1_destination`, `REMOTE_PROVENANCE_UNAVAILABLE`) |
| **H-b** HTTP arm (today's transport, contract-extended) | R's agent via CLI, or R's telesession relay runner (U2) posting the same request | yes: the remote inject response carries `inject_id` (route `daemon.js:4758`; whether the CLI prints it was not measured) | yes, once F reads `relay_context` from the body (T-2) and a sender passes it (U2: R's runner; the CLI would need a flag, not specified here) | nothing beyond §3's residuals once F has T-2…T-6 |
| **H-c** telepty#111 daemon-side forward (planned, Mac-owned, not started) | R's daemon, for an exact remote target | yes: #111 returns the remote inject id + a routing receipt | yes: **#111 MUST forward `relay_context` verbatim** (no rewrite, no drop) and MUST NOT mint receipts on F's behalf | as H-b. #111's routing receipt is **hop evidence only** (`transport_accepted` of R's leg, R1 in base §3), never a destination stage |

**Binding is hop-mode independent.** O's rule (§1.3) depends only on F's signed receipt and O's own
record. It never depends on who carried the request or the receipt. The same B0–B9 apply under H-b and
H-c, and under H-a they simply never succeed. A later move from H-b to H-c changes nothing at O.

---

## 2. Final-inject identification and signing party

### 2.1 Who mints, who attests

| fact | minted / attested by | basis |
|---|---|---|
| I (leg-1 inject) | the daemon that delivered leg 1 to R | its inject route (`daemon.js:4758`) |
| C | O (telesession), at send | `telepty.js:1217-1220`, immutable |
| J (final inject) | F, at its inject route | same code path as I, on F |
| D's stage facts (`agent_consumed`, `processing_completed`, `rejected`) | D, by posting with **its own bearer** to F | F resolves the bearer to `{sid, epoch, generation}` (`daemon.js:359-379`, `session-credentials.js:84`) |
| the receipt object | **F** (the daemon), with its **host receipt key** (Ed25519) | telepty#100 T-3/T-4, does not exist today |

The **signing party is F**, not D and not any hop. D authenticates to F with its bearer (exists). F binds
that principal to J's record (J's `session_id` + `session_epoch` must equal the poster's sid + epoch,
otherwise F refuses the stage post). F then signs.

### 2.2 Signed bytes (receipt v2)

`sig = Ed25519.sign(host_receipt_private_key, "telepty-final-receipt/v1\n" + canonical(body))`,
where `body` has exactly these keys:

```
{ v: 2, correlation_id, origin_inject_id, origin_host, final_inject_id, final_host, final_session,
  final_session_epoch, stage, seq, at, attested_by: { sid, epoch, generation },
  delivered_payload_sha256, key_id }
```

- `canonical()` = JSON with keys sorted by code point at every level, no whitespace, strings in UTF-8,
  integers only (no floats), `null` allowed, no other types. About 15 lines of code, one per side, no
  dependency.
- `final_host` = F's own canonical peer id (the id O's peer table pins the key under). `MACHINE_ID` alone
  is **not** a valid basis: it is self-asserted and settable by environment (`daemon.js:77`). Only the
  signature under a pinned key binds the host.
- `delivered_payload_sha256` = sha256 of the prompt F delivered for J (as the audit already computes,
  `inject-log.js:60`). It is informational corroboration only (§3, residual RS-2).
- `seq` = F's per-J monotonic counter. `at` = F's clock. Neither is used for acceptance.
- `key_id` = F's key identifier (selects the pinned key, allows rotation).
- Carried alongside, **outside** the signed body: `role:"final"`, `auth_basis:"own_bearer"`, `sig`
  (base64url). These are v1-compatible fields for the existing shape checks.

### 2.3 What O verifies with

O verifies against the **pinned public key** for `canonical(final_host)`, taken from O's peer table (the
resolver input, base §9; new optional per-peer `receipt_keys: [{key_id, public_key_spki_b64}]`). There is
no trust on first use, no key fetched from the receipt, and no key fetched from a hop. A peer without
`receipt_keys` → `KEY_UNKNOWN` (fail-closed). Ed25519 runs in `node:crypto`, so Article 17 is satisfied.

### 2.4 Exists today vs telepty#100 (Mac, task 1229)

| need | telepty `db2f532` | telepty#100 must add |
|---|---|---|
| inject id minted per delivery | yes, `daemon.js:4758` | — |
| verified session principal (sid, epoch, generation) from a bearer | yes, `daemon.js:359-379`; audit fields `inject-log.js:47-53` | — |
| session epoch on the tracked-inject record | yes, `daemon.js:679` | — |
| consumption observation per inject | yes, `GET /api/inject-observations/:id`, `daemon.js:5070` | — |
| audit read with `to`/`from` filters | yes, `daemon.js:3767-3779` | T-1: `correlation_id` filter + stored relay context |
| structured relay context on an inject | **no**: inject body destructures `prompt, no_enter, auto_submit, thread_id, reply_expected, from, reply_to, exact_target, ref_path` (`daemon.js:4745-4751`, `ref_path` at `:4790`); other keys are not read | T-2: optional `relay_context` stored immutably on J's record |
| final session posting a stage with its own bearer | **no** route | T-3: `POST /api/injects/:J/receipts {stage}` with D's bearer; refuse unless the bearer's sid+epoch = J's session+epoch |
| host identity | **self-asserted only**: `MACHINE_ID` (`daemon.js:77`), `/api/meta.host`/`machine_id` (`daemon.js:3858-3867`), audit `origin_host` (`daemon.js:4790`) | T-4: host receipt key pair (Ed25519), public key + `key_id` exportable for operator pinning; private key never leaves F |
| signed receipt | **no**. `src/audit/provenance.js:14-21` is a nonce banner and explicitly not a signature | T-5: build + sign body §2.2; serve `GET /api/requests/:C/receipts` (base §9.1 proposed) on F, and deliver/forward to O (T-6) |
| receipt transport back to O | **no** | T-6: F pushes signed receipts to O's daemon over the existing peer link, or O's daemon pulls them. Any path works: signatures make the carrier untrusted |
| capability advertisement | `/api/meta.capabilities` exists (`daemon.js:3867`); no receipt capability | T-7: capability `final-receipts-v2` |
| daemon-side cross-host inject | **no**: local session table only (`daemon.js:4742-4746`); the CLI does the hop (§1.4) | telepty#111 (separate issue): forward for an exact remote target, return the remote inject id + routing receipt, forward `relay_context` verbatim (§1.4 H-c) |

**Not verifiable until telepty#100 lands:** that F really holds the key, signs only facts its own bearer
check accepted, stores `relay_context` immutably, and refuses stage posts from another sid or epoch. Also
that any F-side or transport path exists at all. U1–U6 prove the **origin side** against a synthetic F
(§5). They are not evidence that the telepty side exists or is correct (same disclaimer as base §9.1).

**Constitutional note (Article 1; telepty §1 "watched line", `provenance.js:18-21`).** That line forbids
crypto that an **LLM** "verifies" over its own input. Here the signature is produced by daemon code and
checked by telesession code. No agent verifies anything. It is one primitive (Ed25519 sign/verify), with
no PKI, no chain and no certificate. **Alternative considered:** channel attestation, where O's daemon
stamps `verified_sender_host` from the peer link (base §9.1 today). It is lighter, but every intermediary
daemon on a relayed path becomes trusted, and an O that cannot reach F directly (the "via Linux" case)
gets nothing. Today's hop (§1.4 H-b) also puts F's **peer token** in the hands of the leg-1 host, and
telepty#110 discloses stored peer tokens to any local-token holder there. A channel-attested receipt
could therefore be forged from the leg-1 host. A signed receipt cannot (§3 RS-7). **Recommendation:
signature for relayed receipts; channel attestation remains for direct
records.** This is decision D1, pending in REPORT, recommended default as written. If the orchestrator
picks channel attestation, only B6 and §5's key handling change.

---

## 3. Relayer-forgery trust boundary

Adversary: any R (relaying session, its telesession, its daemon) and any carrier of receipts between F
and O, including O's own host processes **other than** O's telesession and its ledger directory. Same-uid
compromise of O's host is out of scope: such an adversary can edit O's ledger directly. R is trusted for
**what work it forwards** (the origin chose it as its delegate). R is **not** trusted for **whether F
completed it**.

Invariants (each is checkable by a reviewer and has a test row in §6):

- **I-1 (no forgery).** A receipt is applied to a relayed record only if `sig` verifies under a key pinned
  in O's peer table for `canonical(final_host)` (B6). R holds no such key, so R cannot produce an
  acceptable receipt. This holds even when R holds F's peer token (H-b, telepty#110), because the token
  authorises injects, not signatures. T-3 MUST accept a stage post **only** with the destination
  session's own bearer, never with a peer or operator token. → test X1, X2.
- **I-2 (no re-targeting across requests).** The signed body contains both `origin_inject_id` and
  `correlation_id`, and both must equal the same O record (B1, B4). Changing either breaks the signature;
  presenting the receipt under another record fails B1/B4. → X3.
- **I-3 (no re-targeting across endpoints).** `final_host` + `final_session` (+ epoch) are signed and
  must equal `rec.destination` (B7). A genuine receipt from another host or another session, including a
  same-named session on a second host, is refused `SOURCE_MISMATCH`. → X4, S1.
- **I-4 (no cross-origin replay).** `origin_host` is signed and must be O (B5). → X5.
- **I-5 (replay / duplicate).** Applied receipt identities `(canonical final_host, J, stage)` are kept on
  the record (`receipt_keys`, bounded 16). A second receipt with an applied identity is a no-op
  (`deduplicated`), including one re-signed with another `seq`/`at`. A byte-identical replay also
  collapses through the reply and event keys (base §7). Repeated pulls never change state. → X6.
- **I-6 (stale).** A receipt for a terminal (`rejected`) record is refused `STALE_AFTER_TERMINAL`. A
  `rejected` receipt after `origin_ack_received` is refused `REJECT_AFTER_ACK` (base §5, N14). A
  lower-stage receipt after a higher stage fills only a null timestamp. A receipt for a retired record is
  refused `RETIRED`. None of these change `stage`, `ack_seq` or `status`. → X7, X8.
- **I-7 (direct unchanged).** A direct record's acceptance set is exactly the `8016f25` rule (§1.3).
  → B-D1, B-D2, and the existing `e2e-full-route` direct tests unchanged.
- **I-8 (no silent weakening).** A missing key, a missing capability, a missing I or an unparseable
  receipt each refuse with a code. No path falls back to correlation-only binding (HOLD option C stays
  rejected).

What a compromised R **can** still do (availability only, never a false completion):
- drop or delay the forward, or the receipts it carries → O stays `pending`, then `unknown`
  (`DEADLINE_PASSED`), then `expired`. This is base §12's no-unconditional-guarantee model;
- forward the request several times → several genuine J at F (at-least-once; D must use the nonce as its
  idempotency key, base §7). Each J's completion is genuine. The first sets `first_ack_seq`, a later one
  moves `ack_seq` forward (`NEWER_FINAL_ACK_UNREAD`);
- mislabel its lookup of I → O refuses `INJECT_MISMATCH`/`INJECT_UNKNOWN` (availability).

Residuals (accepted, named):
- **RS-1 substitution.** R can forward **different work** under the origin's (I, C). F then genuinely
  signs the completion of that work, and O records `completed`. This is inherent in delegating to R. A
  stronger option would be byte-preserving forwarding with an F-computed hash compared to
  `rec.payload_sha256`. That is not specified: relayers legitimately rewrite tasks, and it would need the
  origin wire bytes at F. It is deferred.
- **RS-2.** `delivered_payload_sha256` is signed but not compared (follows from RS-1). It serves only
  operator forensics.
- **RS-3 F compromise.** Whoever holds F's private key can sign anything for F's destinations. Key storage
  and rotation are telepty#100's (Rule 47, pending).
- **RS-4 D lies.** D can post `processing_completed` without doing the work. Semantic truth is D's (base
  §5: the destination alone produces the semantic ACK).
- **RS-5 epoch.** A destination session re-created after the first applied receipt (new epoch) cannot
  complete the record (`GENERATION_MISMATCH`, base §9.1 learn-once). Recovery is an operator re-issue. A
  daemon restart that keeps the session instance keeps its epoch (`daemon.js:330-331`, credential store
  survives restart; RC5 proves it on the direct path).
- **RS-6 clocks.** `at` is F's clock and is never used for acceptance. Staleness is decided by O's
  record state only.
- **RS-7 peer-token disclosure (telepty#110, current).** `GET /api/peers` discloses stored peer tokens to
  any local-token holder (measured by the U2 coder; not re-measured here). A compromised leg-1 host, or any
  local process holding a local token there, can read F's peer token. It can then inject arbitrary work
  into F's sessions (it widens RS-1 to non-delegates on that host) and see the peer list. It **cannot**
  forge a receipt (I-1: no signing key; T-3: bearer-only). Until #110 is fixed, the peer token is a
  shared secret of every local-token holder on the leg-1 host.
- **RS-8 H-a hop (today's SSH arm).** It cannot prove that a final inject exists, nor its id or session
  (§1.4). A request relayed that way never reaches `completed` through a receipt, which is availability,
  not integrity.

---

## 4. API compatibility and schema deltas

### 4.1 MCP surfaces

| surface | change | compatibility |
|---|---|---|
| `telesession_send` | none in U1. U2 adds the cross-host path, U4 the relay intake (§7) | unchanged |
| `telesession_request_status` | optional output field `receipt_refusals: {code: count}` (last pull, omitted when empty) | additive; §4.4 consumers that ignore unknown keys are unaffected |
| `telesession_read_reply` / addenda | none. A bound relayed completion is a verified reply entry, as the direct path already does (base §9.1). Its text is `[telesession receipt stage=processing_completed]\n<json>`, where the JSON adds `origin_inject_id`, `final_inject_id`, `final_host`, `final_session`, `key_id` | additive keys inside the existing text format |
| `telesession_health` | none (19:27Z decision) | unchanged |
| reply entry `attestation` | a bound relayed receipt is stored with `from` = `rec.destination` → `attestation:"destination"` (existing value) | no new enum value |

### 4.2 Ledger record (base §4.1): new optional fields, `LEDGER_VERSION` stays `1`

| field | type | set by | absent / null means |
|---|---|---|---|
| `origin_inject_id` | string (`^[A-Za-z0-9._:-]{1,128}$`) \| null | `openLedgerRecord` at create (I); reconstructed records: the store's `inject_id` | unknown: relayed receipts refused `INJECT_UNKNOWN`; direct falls back to the store inject (today) |
| `receipt_keys` | list of 64-hex (sha256 of `host/J/stage`), bounded 16 | applying a relayed v2 receipt | empty |

Why no version bump: `isRecord` (`ledger.js:90-99`) checks named fields and does not reject extra keys.
`commit` deep-copies state with `structuredClone` (`ledger.js:297`), which keeps unknown keys. So an
`8016f25` build opens and rewrites a ledger written by U1 code without loss. Bumping `LEDGER_VERSION`
would make that older build refuse the file (`LEDGER_VERSION_UNSUPPORTED`, `ledger.js:283`) and break
rollback. U1 code MUST validate both fields when present (shape and bound), so a tampered value is
`LEDGER_CORRUPT` as for other fields. The store schema is **not** touched: `STORE_VERSION` and its
exact-key check (`store.js:52-55`) stay as they are.
Byte margin: `origin_inject_id` adds at most about 160 B to a record at create. The test-measured worst
case of 5669 B (`ledger.js:50`) stays under `RECORD_MARGIN_BYTES` 8192. `receipt_keys` is written after
create, outside the reserved margin, and counts toward the 4 MiB bound like `events`.

### 4.3 Receipt schema versions

- v1 (base §9.1, today): no `origin_inject_id`, no `sig`. Accepted only for direct records under the
  `8016f25` rule.
- v2 (§2.2): `v:2` + the signed body + `sig`. Accepted for relayed records under B0–B9. For a direct
  record a v2 receipt is checked under the direct rule (its `final_inject_id` must be in the known-inject
  set). The signature is verified when a key is pinned. If no key is pinned, the receipt is treated as v1.

### 4.4 Migration and rollback

- Forward: no migration step. Records created before U1 have no `origin_inject_id`. Direct ones keep
  binding through the store inject (until it is purged, as today). Relayed ones keep being refused
  (`INJECT_UNKNOWN`), and their completion stays reachable only through the leg-1 addendum path.
- Rollback to `8016f25`: revert the U1 commits. The ledger opens unchanged (§4.2), and the extra fields
  are carried along unread. Relayed receipts go back to `INJECT_MISMATCH`. Records already `completed`
  through a bound relayed receipt stay `completed`: their reply entry and stages are ordinary fields.
- Nothing changes live by default. The default receipt adapter stays `NO_RECEIPTS` and the peer table has
  no `receipt_keys`, so every v2 path is inert until an operator pins keys and enables a receipt adapter.
  Enabling either is a separate approval (base §10 activation rule).

### 4.5 Rule 47 items (cited, not decided)

| item | recommended default |
|---|---|
| storage of F's private key (telepty) | F's data dir, file 0600, generated on first start, never exported; public key exportable |
| pinning store for `receipt_keys` (telesession) | the operator-supplied peer table (same source as the resolver), read-only to telesession, no TOFU |
| key rotation / revocation | a list of `key_id`s per peer; removing a key_id revokes it; receipts under it → `KEY_UNKNOWN` |
| retention of `receipt_keys` / refusals | lives and retires with the record (7 days, base §6.1) |
| auth scope of `POST /api/injects/:J/receipts` | D's own bearer only; no operator or peer token |

---

## 5. Synthetic fixture contract (`test/helpers/fake-receipts.js`, `test/helpers/fake-telepty.js`)

The fixture stands in for telepty#100 T-1…T-7 on F. It MUST NOT be taken as evidence that those exist.

**Keys.** `createFakeReceiptSeam({mode, host, keys})`: when `keys` is absent, the seam calls
`generateKeyPairSync("ed25519")` once per seam instance, **in the test process**. Keys are never written
to disk, never read from the environment or the filesystem, and never shared across seams. The seam
exports only `publicPeerEntry()` → `{peer_id: host, locators:[host], receipt_keys:[{key_id, public_key_spki_b64}]}`
for O's peer table, plus a second synthetic key pair (`otherKeys`) for forgery cases. No helper accepts or
emits a real key. A test-runner guard asserts that no file under the sandbox contains the PEM header
`PRIVATE KEY`.

**Minting.** `finalDaemon({sid, epoch})`:
- `send(item)`: as today (`fake-receipts.js:37-44`), plus it reads `item.relay_context` (or
  `envelope.relay_context` for the JSON-envelope path). It refuses `RELAY_CONTEXT_INVALID` unless the
  context is well-formed with `final.session === sid` and `final.host === host`. It mints J =
  `randomUUID()` and stores `{J, relay_context, session: sid, epoch, delivered_payload_sha256}`
  immutably.
- `attest(J, stage, opts)`: builds the §2.2 body from the stored J record (never from caller input) and
  signs with the seam key. `seq` is per J.
- `observe(...)` unchanged.

**Adversarial producers** (each returns a receipt object; none mutates stored state):

| helper | produces | expected at O |
|---|---|---|
| `forge(J, stage, {key: otherKeys})` | valid body signed with an unpinned key | `KEY_UNKNOWN` (unknown `key_id`) or `SIGNATURE_INVALID` (pinned `key_id`, wrong key) |
| `tamper(receipt, field, value)` | the signed receipt with one body field changed after signing (relayer modification) | `SIGNATURE_INVALID` |
| `retarget(receipt, {origin_inject_id \| correlation_id \| final_session \| final_host \| origin_host})` | re-signed with the **seam** key (a genuine F signing a different fact) | `INJECT_MISMATCH` / `CORRELATION_MISMATCH` / `SOURCE_MISMATCH` / `ORIGIN_MISMATCH` |
| `replay(receipt)` | the same object posted again | `deduplicated`, no state change |
| `resign(receipt, {seq, at})` | same identity, new seq/at, valid signature | `deduplicated` (I-5) |
| `stale(J, stage)` | a valid receipt posted after the record became terminal or retired | `STALE_AFTER_TERMINAL` / `RETIRED` |
| `unsigned(J, stage)` | v1 shape (no `v`, no `sig`) for a relayed record | `INJECT_MISMATCH` / `INJECT_UNKNOWN` (today's refusal) |

**`fake-telepty.js`** (models the daemon O and R inject into): adds `relay_context` passthrough on
`POST /api/sessions/:id/inject` and stores it on the audit row. It adds the `correlation_id` filter on
`/api/injects` (T-1). It advertises `final-receipts-v2` only when constructed with `{receiptsV2:true}`
(capability absent by default, as on `db2f532`). Existing facts F1–F5 (`fake-telepty.js:1-25`) are
unchanged.

---

## 6. Test matrix

Unit / isolated rows (U1, U5) live in `test/e2e-full-route.test.js` and `test/relay-receipt-binding.test.js`
(new). The latter must be added to the test-runners guard list.

| id | case | setup | expected |
|---|---|---|---|
| B-D1 | binding success, direct | direct send; v1 proven receipts naming `s.inject_id` | `origin_ack_received` → `completed` after the checkpoint (existing test, unchanged) |
| B-D2 | direct after store purge | as B-D1, store record purged (clock past the store retain), ledger live | still bound through `rec.origin_inject_id` (fails on `8016f25`: `INJECT_UNKNOWN`) |
| B-R1 | binding success, relayed | O → R (fake-telepty) → R relay runner with relay_context {C, I} → seam F; F signs `agent_consumed`, `processing_completed` | `applied 2`; stage `origin_ack_received`; reply `attestation:"destination"`, body names I + J; `completed` after the checkpoint |
| B-R2 | relayed, no pinned key | as B-R1, peer table without `receipt_keys` | `KEY_UNKNOWN ×2`; pending; no marker |
| B-R3 | relayed, legacy v1 receipt | `unsigned()` | refused as today; pending |
| X1 | forged by relayer | `forge(..., otherKeys)` | `KEY_UNKNOWN` or `SIGNATURE_INVALID`; status unchanged |
| X2 | relayer-modified | `tamper(r, "stage", "processing_completed")` on an `agent_consumed` receipt | `SIGNATURE_INVALID` |
| X3 | re-targeted to another request | two O records; F's receipt for record 1 presented under record 2's correlation; `retarget` with record 2's I | `CORRELATION_MISMATCH` / `INJECT_MISMATCH`; record 2 unchanged |
| X4 | re-targeted endpoint | `retarget(final_session)` / `retarget(final_host)` | `SOURCE_MISMATCH` |
| X5 | cross-origin replay | `retarget(origin_host)` | `ORIGIN_MISMATCH` |
| X6 | replayed / duplicate | `replay`, `resign`, two pulls | `deduplicated`; one reply, one seq; `ack_seq` unchanged |
| X7 | stale after terminal | F `rejected` applied, then `processing_completed` | `STALE_AFTER_TERMINAL`; status `rejected` |
| X8 | rejected after ACK / retired | `processing_completed` then `rejected`; record past `retain_until` | `REJECT_AFTER_ACK`; `RETIRED`; `completed` stays |
| S1 | same-name target, two hosts | peer table `peer-a`, `peer-b`, both with session `w` and both pinned; destination `peer-b/w`; a genuine `peer-a/w` receipt naming the same I + C | `SOURCE_MISMATCH`; the `peer-b/w` receipt applies. U2 repeats this on the real send path (U6 harness) |
| L1 | I lookup ambiguous at R | two leg-1 injects from the same inbox to R in one window, interim lookup | `ORIGIN_INJECT_AMBIGUOUS` at R; O refuses `INJECT_UNKNOWN`; no false completion |
| L2 | hop limit | relay_context `hop:4` re-relayed | `RELAY_HOP_LIMIT`, outbox `failed` |
| RS1 | re-send after transport failure | R's first relay send `sent:"no"` (fake refuses once) → requeued → sent (J2) | one J applied; O completes; outbox attempts 2 |
| RS2 | re-send creating two J | R forwards twice (operator re-enqueue) → J1, J2 both complete | first completion sets `first_ack_seq`; J2 moves `ack_seq` forward, `NEWER_FINAL_ACK_UNREAD`; no duplicate seq |
| RC1 | origin restart mid-flow | reopen O's ledger and transport between the relay send and F's receipts | receipts bind after reopen (I persisted in the ledger); seq/cursor continue |
| RC2 | daemon restart (RC5-style, real daemon) | U4: real telepty from `TELESESSION_TEST_TELEPTY_DIR`; leg-1 inject accepted; daemon restarted on the same HOME and port; relay continues | I and C unchanged; the wrapped R keeps its epoch; O completes from F's signed receipt. Gated as the real-daemon set (docs/ci.md), never the operational daemon |
| C1 | compat | 8016f25 ledger fixture opened by U1 code; U1 ledger opened by the 8016f25 `isRecord` | both open; fields preserved; no version error |
| H1 | hop mode H-a (SSH arm, no J, no relay_context) | R forwards without relay_context; F mints J without context | F can produce no v2 receipt; any receipt for J is refused (`INJECT_UNKNOWN`/`INJECT_MISMATCH`); O stays pending, then unknown; a leg-1 addendum still arrives as `relayed_by_leg1_destination` |
| H2 | hop mode H-b vs H-c | the same relayed flow, once with R posting to F directly (HTTP arm) and once through a fake #111 forward on R's daemon that returns J + a routing receipt | identical O outcome (`completed`). The #111 routing receipt maps only to R's leg `transport_accepted`, never to a destination stage at O |
| H3 | #111 drops or rewrites relay_context | the fake forward strips `relay_context` / changes `origin_inject_id` | the F receipt lacks I → `INJECT_UNKNOWN`; or it names another I → `INJECT_MISMATCH`; never completed |

**U6 two-daemon isolated E2E harness (design).** All harness processes are started and stopped by the
test. The operational daemon is never touched.
- Two telepty daemons from `TELESESSION_TEST_TELEPTY_DIR` through `startRestartableTeleptyDaemon`
  (`test/helpers.js:294-316`). Each has its own temp `HOME` (data dir, credential store, audit), its own
  `PORT` (0 → bound port read back) and its own `TELEPTY_MACHINE_ID` (`host-k`, `host-m`). The labels are
  self-asserted and are used only as peer ids in each side's peer table.
- Two telesession endpoints (transports with their own state dirs and ledgers). **K-side** (origin) points
  at daemon `host-k`. **M-side** points at daemon `host-m`. A relaying R (an "L" stub session) is
  registered on `host-k` for the via case.
- **The cross-host hop is driven by a stub leg-1 relayer**, because no daemon forwards across hosts
  (§1.4). The stub models today's hop (H-b, HTTP arm). On receiving the leg-1 prompt on `host-k`, it:
  1. looks up I on `host-k` (§1.2 b);
  2. posts `POST /api/sessions/<w>/inject` with `exact_target:true` and `relay_context` **directly to
     daemon `host-m`'s port**, presenting a **test-only peer entry**: `{name:"host-m",
     transport:"http", host:"127.0.0.1", port:<host-m port>, token:<synthetic>}`, written only into the
     harness temp `HOME/.telepty/peers.json` of the stub's environment;
  3. records J from the response.
  The synthetic token is `randomBytes(32)` minted in the test, set as daemon `host-m`'s
  `TELEPTY_AUTH_TOKEN` in that daemon's env, never logged, never written outside the temp `HOME`, and
  discarded with it. The real `~/.telepty/peers.json` and any real token are never read: the harness
  asserts that `HOME` points into its temp dir before it starts anything. The stub posts the same request
  the CLI's HTTP arm makes (`cross-machine.js:443-509`). It does not shell out to the CLI. Driving the
  real CLI is optional, and only with the same temp `HOME`. An H-a variant (no J, no relay_context) is
  row H1. Once telepty#111 lands, an H-c variant replaces step 2 with an inject to `w@host-m` on
  `host-k` (row H2).
- Stubs are wrapped sessions spawned from test-support children, as RC5 does. The **Kkoma stub** is O's
  origin agent (it calls send/request_status). The **Mac stub** is D on `host-m`: it reads its prompt and
  posts stage facts with its own bearer.
- F in the harness: until telepty#100 exists, a **harness receipt shim** in the test process plays T-2…T-6
  for `host-m`. It records relay context per inject, accepts the Mac stub's stage posts, verifies the
  bearer against `host-m`'s audit (`verified_sender_sid` + epoch), signs with a synthetic key and serves
  receipts to K-side's receipt adapter. The shim is named as such in the test output. Once telepty#100
  lands, it is removed and the same rows run against the real T-routes.
- Cases: (a) direct K → M; (b) via K → L → M; (c) same-name `w` on both daemons, destination `host-m/w`;
  (d) X1/X3/X6/X7 on the real wire; (e) `host-m` restart between delivery and the Mac stub's post (RC2);
  (f) H1 (SSH-arm-like hop, no J): stays pending, never completed.
  Pass = the Kkoma correlation reaches `completed` after the stub's checkpoint, with no manual step.
  Uses loopback only, and is skipped with `NOTRUN` when loopback is not permitted (as `e2e-full-route`
  does).
- U6(b), a real Linux↔Mac run with test daemons, needs Mac participation and is outside U1.

---

## 7. Implementation plan for the U1 code

Order (each step lands with its failing-first tests from §6):

1. **`src/relay/receipt-sig.js`** (new, about 50 lines): `canonicalJson(v)`, `RECEIPT_SIG_DOMAIN`,
   `verifyReceiptSig(receipt, pinnedKeys)` → `{ok} | {ok:false, code: "KEY_UNKNOWN"|"SIGNATURE_INVALID"}`
   using `crypto.verify(null, bytes, createPublicKey({key, format:"der", type:"spki"}), sig)`. There is no
   signing in `src/`: signing lives only in the fixture.
2. **`src/relay/route.js`** (about 20 lines): accept optional `receipt_keys` per peer (validated:
   `key_id` `^[A-Za-z0-9._:-]{1,64}$`, SPKI base64 ≤ 128 chars, ≤ 4 per peer); `receiptKeys(peerId)` →
   map. Existing resolver behaviour is unchanged.
3. **`src/relay/ledger.js`** (about 40 lines): `createRequest` accepts `origin_inject_id`. `isRecord`
   validates `origin_inject_id` and `receipt_keys` when present. New `noteReceipt(nonce, identitySha)`,
   or `receipt_key` on `recordEvent`, appends to `receipt_keys` (bounded 16) **in the same commit** as the
   event. `recordEvent` returns `deduplicated` when the identity is present. `LEDGER_VERSION` is
   unchanged.
4. **`src/relay/adapters.js`** (about 60 lines): `isReceiptV2(r)`. `applyReceipts` gains a `pinnedKeys`
   resolver and an `originHost`. If `rec.via !== null` → the B0–B9 path (v2 only; v1 → today's
   refusals). If `rec.via === null` → today's code path untouched (I-7). A terminal record →
   `STALE_AFTER_TERMINAL` before the ledger call. The stored reply JSON adds the §4.1 keys.
5. **`src/transports/telepty.js`** (about 25 lines): `openLedgerRecord` passes `origin_inject_id:
   b.inject_id`. `reconcileLedger` passes `q.inject_id`. `pullReceipts` uses `lr.origin_inject_id ??
   q.inject_id` for the known set, and passes `pinnedKeys` from the configured resolver and
   `originHost: LOCAL`. `requestStatus` attaches `receipt_refusals` from the last pull.
6. **`test/helpers/fake-receipts.js` / `fake-telepty.js`**: §5. **Tests**: §6 rows B-*, X*, S1, L2, RC1,
   C1 (U1). L1, RS1, RS2, RC2 are U4. U6 is the harness.
7. **Spec/CHANGELOG**: base §9.1 pointer (done in this commit). Add a CHANGELOG entry under the next
   release.

Size: about 250 lines of `src/` and about 450 lines of tests and fixtures. That is 2 coder loops + 1
review (plan §3 estimate holds).

**What later units need from this spec:**
- U2 (cross-host send): no daemon forward exists (§1.4). Until telepty#111 lands, the telesession relay
  path is H-b: R's runner posts to F's daemon over the HTTP arm with the peer entry, takes J from the
  response and passes `relay_context` in the body. With #111 it becomes H-c behind a capability check, with
  no change at O. Return the remote inject id as I where telesession performs a cross-host leg 1. Run S1
  and H1–H3 on the real send path.
- U3 (real adapter, after telepty#100): implement T-1…T-7 consumers. Remove the U6 shim. Ensure v2 field
  names and the signature domain match §2.2 exactly.
- U4 (re-send/recovery + relay intake): R-side I lookup (§1.2 a/b, `ORIGIN_INJECT_AMBIGUOUS`), the
  verbatim relay_context copy, `RELAY_HOP_LIMIT`, rows L1, RS1, RS2, RC2.
- U5 (forged/stale/duplicate E2E): rows X1–X8 on the U6 harness.
- U6: §6 harness design.

## 8. Open decisions (pending, with recommendation)

- **D1** signature (recommended) vs channel attestation for relayed receipts (§2.4 note).
- **D2** the interim I lookup (§1.2 b) vs waiting for telepty#100 T-1. Recommended: ship (b). It fails
  closed on ambiguity.
- **D3** Rule 47 items in §4.5 (recommended defaults listed).
