# SPEC — relayed-receipt binding protocol (task #2026101110, plan unit U1; issues #8, #7, #2)

Status: draft, revision 2 (answers independent review 1, verdict REVISE,
orchestrator `state/reviews/1110/2026-10-16-u1-review.md`). Companion to
`2026-10-11-e2e-delivery-protocol.md` (the "base spec"); its §9.1 points here. Nothing in the base spec is
changed except that pointer: the direct-record rule of `8016f25` stays as it is for local direct records
(§1.3).

Revision 2 changes: BLK-1 host identity is F's key fingerprint, and no node-local host name is echoed or
compared (§1.2, §1.2.1, §1.3, §2.2, §2.3). BLK-2 session-name squatting is residual RS-9, and v2 receipts
stay off until upstream precondition P-1 holds (§2.5, §3). BLK-3 cross-host "direct" is defined, path
selection is by destination, and a missing key is a typed refusal (§1.3, §4.3). BLK-4 has no H-b
telesession path; the only telesession cross-host path is telepty#111 (§1.4, §7). N1–N8 are applied
inline and listed in REPORT.
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
  daemon-side cross-host inject today (§1.4), and telesession's send is local-only (`telepty.js:1231-1233`,
  U2 fails closed on a non-local peer). So I is known to telesession only when telepty#111 (H-c) returns
  the remote daemon's inject response. Until then telesession creates no cross-host leg-1 record at all.
- Cross-host **direct** record (O → D on F, no R; needs telepty#111): O's own daemon forwards to F. F
  mints the only inject, so I = J = the remote inject id that #111 returns to O. The record has
  `via === null` and `destination.host` ≠ `local` (§1.3, path S).

O persists I in the **ledger record** (new optional field `origin_inject_id`, §4.2), set in
`openLedgerRecord` from `b.inject_id`. Today `pullReceipts` reads the inject from the **store**
(`telepty.js:1416-1418`). The store purges a request after TTL + 1 day (`store.js:23`,
`telepty.js:1226`), while the ledger keeps it for 7 days (`ledger.js:23`). So between day 1 and day 7, even
a direct receipt is refused `INJECT_UNKNOWN` today. Persisting I in the ledger closes that gap too
(measured from source, not from a run).

### 1.2 Relay context: how I and C travel through every hop

Every relayed leg carries a **relay context**:

```
relay_context = { v: 2, correlation_id: C, origin_inject_id: I | null, final_session: <D sid>, hop: <int 1..4> }
```

The context carries **no host name**. Host names are per-node: O's own host is the literal `"local"`
(`telepty.js:473`), and every peer id is an entry in the node's own resolver table ("Alias consistency
across nodes is telepty work (#105)", `route.js:4-5`). A host name written at one node therefore means
nothing at another (review BLK-1). Host identity is carried by F's signing key instead (§1.2.1).

- **O → R (leg 1).** C is already on the wire header (`[telesession nonce=… reply-to=… correlation=C]`,
  `telepty.js:1220`). I cannot be on the wire because the daemon mints it after the bytes are built.
  R obtains I from **its own daemon** by one of these two paths:
  (a) **telepty#100 T-1 (target):** the inject body gains optional `relay_context`. O passes
  `{v:2, correlation_id:C}` on leg 1. The delivering daemon stores it on the audit row and the
  tracked-inject record. R reads `GET /api/injects?to=<R>&correlation_id=C` and gets exactly one row,
  whose `inject_id` is I.
  (b) **Interim, no telepty change:** R's telesession reads `GET /api/injects?to=<R>&since=<t0>&until=<t1>`
  (filters exist: `daemon.js:3767-3779`). The record window is `t0 = arrival − 300 s`,
  `t1 = arrival + 5 s`, where `arrival` is R's clock when its telesession read the leg-1 prompt. R does
  **not** use the `from` filter: it matches `claimed_from` **or** `verified_sender_sid`
  (`inject-log.js:211`), so any local-token holder on R's daemon could plant a row with a claimed `from`
  (review N3). R keeps only rows with `verified_sender_sid === <reply-to inbox>` (O's send carries the
  inbox bearer, `telepty.js:1231-1233`, so a genuine leg-1 row is verified). It accepts I only if exactly
  one row remains. Otherwise I = null (`ORIGIN_INJECT_AMBIGUOUS`, counted in R's outbox item), and the
  relayed receipt is later refused at O (`INJECT_UNKNOWN`). This is an availability residual (RS-11).
  A wrong I cannot complete another request: the binding (§1.3) needs I **and** C to match the **same**
  O record, and C is O-minted, 128-bit (`telepty.js:1217`). A lookup error therefore yields a refusal,
  not a completion of another record.
- **R → F.** R's telesession relay send goes through R's **own** daemon and telepty#111 (H-c, §1.4).
  It passes `relay_context` in the inject body (telepty#100 T-2), with `hop + 1`. R copies
  `correlation_id` and `origin_inject_id` **verbatim** from its inbound context. These are immutable along
  the route. `final_session` = the exact session id of R's outbox destination. That is F's own session id
  (`exact_target` own-property match, `daemon.js:4742-4747`), so it means the same thing at every node.
  R's name for F's host is used only for R's routing and is never echoed. `hop > 4` is refused by R
  (`RELAY_HOP_LIMIT`, outbox `failed`). The relay envelope text stays the work payload. The relay context
  is out-of-band (in the body, not in the prompt), so D's agent never needs to parse or echo it.
- **F.** The daemon that delivers J to its **local** session `final_session` mints J at its inject route
  (as at `daemon.js:4758`). It refuses the context if `final_session` is not the session it resolved for J
  (`RELAY_CONTEXT_INVALID`). F makes **no** "is this host me" check: F has no host id that other nodes
  share. If R misroutes to another daemon G, G signs with G's key, and O refuses it (§1.3 B5). F stores
  `relay_context` on J's tracked-inject record immutably, next to `session_id` and `session_epoch` (as at
  `daemon.js:679`). It echoes that context in every receipt for J (§2). D cannot change it: D only posts
  stage facts with its own bearer.

#### 1.2.1 Who names what, in whose namespace (BLK-1)

| value | authored by | namespace | travels to | compared at O against |
|---|---|---|---|---|
| C | O (`telepty.js:1217`) | global (random 128-bit) | wire header, context, signed body | `rec.correlation_id` (B1) |
| I | O's leg-1 daemon / R's lookup | that daemon's id space, opaque | context, signed body | `rec.origin_inject_id` (B4) |
| J | F (`daemon.js:4758`) | F's id space, opaque | signed body, `inject_id` | dedupe identity only (B9); for a cross-host direct record, `rec.origin_inject_id` (B4d) |
| D sid | F (session registry) | F's sessions; exact ids are the same string at every node | context, signed body | `rec.destination.session` (B7) |
| O's name for F | O's peer table | **O only** | nowhere | selects the pinned key set (B5) |
| R's name for F | R's peer table | **R only** | nowhere (R's routing only) | — |
| F's self-label (`MACHINE_ID`, `daemon.js:77`) | F, self-asserted | none | nowhere (not in the signed body) | — |
| **host identity** = `key_id` = `"ed25519:" + base64url(sha256(SPKI DER))` of F's receipt key | derived from F's public key bytes | **global** (self-certifying) | signed body | key set pinned under O's own name for `rec.destination.host` (B5) |

So O, R and F may name the same hosts differently, and a genuine receipt still binds. Host integrity
rests on B5/B6 only: O picks the keys from its **own** record and its **own** peer table. No dependency on
telepty#105 (cross-node alias consistency) exists for integrity. #105 matters only for R's routing (R must
resolve O's intended host in its own table). A routing error at R is a refusal at O (wrong key, B5), not
a false completion.

### 1.3 What the final receipt echoes, and the binding rule at O

A **v2 receipt** (§2.2) carries the signed body (`v:2`, `correlation_id`, `origin_inject_id`,
`final_inject_id` (J), `final_session`, `final_session_epoch`, `stage`, `seq`, `at`,
`attested_by {sid, epoch, generation}`, `delivered_payload_sha256`, `session_guard`, `key_id`) plus the
unsigned v1-compatible fields `inject_id` (= J), `role`, `auth_basis`, `sig`. Because `inject_id` is
present, every v2 receipt also passes the existing `isReceipt` shape (`adapters.js:51`, review BLK-3).

**Path selection (by record, never by receipt).** Let `remote = canonical(rec.destination.host) !== "local"`.
- **Path D (local direct):** `rec.via === null && !remote`. This is the only direct record that exists
  today (send is local-only, `telepty.js:1231-1233`). The `8016f25` rule applies, unchanged (below).
- **Path S (signed):** `rec.via !== null || remote`. This covers every relayed record and the cross-host
  direct record of telepty#111 (§1.1). Here the signature is **mandatory**, and the provenance adapter
  is not consulted.

**Binding rule on path S (fail-closed, evaluated in this order, the first failing check refuses):**

| # | check | refusal code |
|---|---|---|
| B0 | `isReceipt(r)` and v2 shape (bounded fields, `r.v === 2`, `inject_id === final_inject_id`). A v1 receipt (no `v`/`sig`) on path S → `SIGNATURE_REQUIRED` | `INVALID_RECEIPT` / `SIGNATURE_REQUIRED` |
| B1 | `correlation_id === rec.correlation_id` | `CORRELATION_MISMATCH` |
| B2 | `role === "final"` / `auth_basis === "own_bearer"` (unchanged) | `HOP_FACT_ONLY` / `NOT_OWN_BEARER` |
| B3 | `rec.origin_inject_id` is a string (O knows its inject) | `INJECT_UNKNOWN` |
| B4 | relayed: `receipt.origin_inject_id === rec.origin_inject_id`. **B4d** cross-host direct: `receipt.final_inject_id === rec.origin_inject_id` and `receipt.origin_inject_id === null` | `INJECT_MISMATCH` |
| B5 | `key_id` ∈ the keys pinned in O's peer table under `canonical(rec.destination.host)` (O's own record and O's own name; §1.2.1). If none are pinned there, or the `key_id` is unknown → `KEY_UNKNOWN`. If the `key_id` is pinned under **another** peer and the signature verifies under it → `SOURCE_MISMATCH` | `KEY_UNKNOWN` / `SOURCE_MISMATCH` |
| B6 | signature verifies under the B5 key (§2.2) | `SIGNATURE_INVALID` |
| B6g | signed `session_guard === "peer-scope-v1"` (F asserts upstream precondition P-1, §2.5) | `F_GUARD_ABSENT` |
| B7 | `final_session === rec.destination.session` and `attested_by.sid === final_session` and `attested_by.epoch === final_session_epoch` | `SOURCE_MISMATCH` |
| B8 | record not terminal, not retired; stage rules of base §5 (`GENERATION_MISMATCH`, `REJECT_AFTER_ACK`, …) via `ledger.recordEvent` | the ledger's code; terminal → `STALE_AFTER_TERMINAL` |
| B9 | receipt identity `(canonical(rec.destination.host), J, stage)` not already applied (§3, I-5) | not a refusal: `deduplicated` |

There is no host-name comparison. The former `origin_host` check is removed: a name written by R in R's
namespace verified nothing at O (review BLK-1). Cross-origin replay is stopped by C and I (I-4).

Accepted iff B0–B8 pass. On acceptance the receipt is applied as a **proven** destination event, with
`from = rec.destination` (base §9.1: `processing_completed` → verified reply entry →
`origin_ack_received` → `completed` after the checkpoint). Path S has no "unproven" outcome. A receipt
that fails B0–B6g is refused with its code, changes no state, and sets no `REMOTE_PROVENANCE_UNAVAILABLE`
marker. A valid signature **replaces** the provenance-adapter proof on path S; a failed one is never
downgraded to an unproven or v1 evaluation (I-8). The existing marker path (the transport's relayed
final reply via the leg-1 target, base §9.1) stays as it is.

**Counting.** Refusals are counted per pull in the `applyReceipts` result (`refused[code]`, as today).
They are also exposed in the status view as the optional `receipt_refusals` (last pull only, so repeated
polls do not inflate counts, §4.1). The 19:27Z decision (no health counter) stands. `pullReceipts`
returns early for a terminal record (`telepty.js:1413`). So `STALE_AFTER_TERMINAL` is reachable only
when `applyReceipts` is called directly, and it never appears in `receipt_refusals` (review N4).

**Path D (local direct records): unchanged from `8016f25`.** They keep the known-inject set
(`adapters.js:76-77`; the set is now `{rec.origin_inject_id ?? store inject_id} ∪ outbox transport_ids`),
the provenance-adapter host proof and the ledger source check. The receipt's `inject_id` is checked, as
today. A v2 receipt on path D is evaluated by exactly that rule, using its `inject_id`. Its
`origin_inject_id`, `sig` and other v2 fields are ignored, never a substitute for O's own inject. That is
not a downgrade: path D never used signatures. A v1 receipt on path D keeps today's behaviour exactly.
Relayed v1 receipts are still refused, but with `SIGNATURE_REQUIRED` instead of `8016f25`'s
`INJECT_MISMATCH`/`INJECT_UNKNOWN`. The outcome (refused) is unchanged; only the code differs.

### 1.4 Hop model: who performs the cross-host hop (today vs planned)

Measured in telepty `db2f532`. Most of it was measured by the U2 coder and relayed in the orchestrator
note; this author re-read the inject route, the CLI HTTP arm and `fetchWithAuth`.
- `POST /api/sessions/:id/inject` resolves the **local** session table only (`daemon.js:4742-4746`:
  `exact_target` → own-property match → 404 for `sid@host`; otherwise a local alias via
  `resolveSessionAlias`, `daemon.js:3430`).
- The bus auto-route strips `@host` and delivers locally (`daemon.js:5433`).
- `GET /api/sessions` is local only.
- `sid@host` routing is **client-side, in the CLI** (`cli.js:3483` → `session-routing.js`). It has two
  arms:
  - **SSH arm:** runs `telepty inject` on the peer and returns `{success:true}`. There is no inject id and
    no receipt (`cross-machine.js:329-347`).
  - **HTTP arm:** `cli.js:3548` posts directly to the **remote** daemon's inject route through
    `fetchWithAuth`, with that peer's token (stored by `connectHttp`, `cross-machine.js:443-509`, at about
    `:497`). It prints the remote `inject_id` (`cli.js:3566`). `fetchWithAuth` also sends the caller's
    `TELEPTY_SESSION_TOKEN` to whatever daemon URL it targets (`cli.js:297-303`, RS-10).

So **no daemon and no telesession performs a cross-host hop today**. A hop is performed, if at all, by a
**session** on the leg-1 host (the relaying agent R) through the CLI. That is outside telesession.
**telesession itself never posts to a remote daemon with a peer token.** The orchestrator rejected that
(U2 HOLD fork 3, `state/reviews/1110/2026-10-12-u2-REPORT.md:3`), and U2 fails closed on a non-local peer
(`PEER_UNSUPPORTED`/`PEER_UNKNOWN`). Hop modes:

| mode | performed by | J known | relay_context reaches F | what it cannot prove |
|---|---|---|---|---|
| **H-a** agent hop, SSH arm (today, outside telesession) | R's **agent** via CLI | no | no (the CLI has no such option) | the existence, identity and session of the final inject. F cannot echo I/C, so no v2 receipt can exist |
| **H-b** agent hop, HTTP arm (today, outside telesession) | R's **agent** via CLI | printed to R's agent (`cli.js:3566`), but never reaches O or R's telesession as data | no (no CLI option; none is specified here) | the same as H-a. J is an unbound line of agent output, so no v2 receipt can exist. The hop also hands R's session bearer to F's host (RS-10) |
| **H-c** telepty#111 daemon-side forward (planned, Mac-owned, not started) — **the only telesession cross-host path** | R's daemon (relayed) or O's daemon (cross-host direct), for an exact remote target | yes: #111 returns the remote inject id + a routing receipt | yes: **#111 MUST forward `relay_context` verbatim** (no rewrite, no drop) and MUST NOT mint receipts on F's behalf | nothing beyond §3's residuals once F has T-2…T-6 and P-1 (§2.5). #111's routing receipt is **hop evidence only** (`transport_accepted` of the forwarding leg, R1 in base §3), never a destination stage |

Under H-a and H-b the record stays pending → unknown. A completion reaches O only as the leg-1 addendum
(`relayed_by_leg1_destination`, `REMOTE_PROVENANCE_UNAVAILABLE`). That is availability, not integrity
(RS-8). Until #111 lands, U2's telesession cross-host send stays fail-closed.

**Binding is hop-mode independent.** O's rule (§1.3) depends only on F's signed receipt and O's own
record. It never depends on who carried the request or the receipt. B0–B9 succeed only under H-c, and
under H-a/H-b they never succeed.

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
{ v: 2, correlation_id, origin_inject_id, final_inject_id, final_session, final_session_epoch,
  stage, seq, at, attested_by: { sid, epoch, generation }, delivered_payload_sha256,
  session_guard, key_id }
```

- `canonical()` = JSON with keys sorted by code point at every level, no whitespace, strings in UTF-8,
  integers only (no floats), `null` allowed, no other types. About 15 lines of code, one per side, no
  dependency.
- No host name is signed (§1.2.1). `key_id` = `"ed25519:" + base64url(sha256(SPKI DER of F's receipt
  public key))` is F's host identity. Every node computes it from the same public key bytes, so it needs
  no shared naming. `MACHINE_ID` is **not** a valid basis: it is self-asserted and settable by environment
  (`daemon.js:77`). Only the signature under a key pinned at O binds the host.
- `origin_inject_id` = I for a relayed J, `null` for a cross-host direct J (§1.1: there, I = J).
- `session_guard` = `"peer-scope-v1"` when F enforces precondition P-1 (§2.5), else `null`. F signs its
  own policy. O cannot check it independently, so a lying F is RS-3.
- `delivered_payload_sha256` = sha256 of the prompt F delivered for J (as the audit already computes,
  `inject-log.js:60`). It is informational corroboration only (§3, residual RS-2).
- `seq` = F's per-J monotonic counter. `at` = F's clock. Neither is used for acceptance.
- `key_id` also selects the pinned key and allows rotation (a new key has a new fingerprint).
- Carried alongside, **outside** the signed body: `inject_id` (= `final_inject_id`), `role:"final"`,
  `auth_basis:"own_bearer"`, `sig` (base64url). These are v1-compatible fields for the existing shape
  checks (`isReceipt`, `adapters.js:48-56`).

### 2.3 What O verifies with

O verifies against the **pinned public keys** listed in O's peer table under O's **own** name for the
record's destination, `canonical(rec.destination.host)` (the resolver input, base §9; new optional
per-peer `receipt_keys: [{key_id, public_key_spki_b64}]`). The receipt's host claims are not used for key
selection. There is no trust on first use, no key fetched from the receipt, and no key fetched from a hop.
A peer without `receipt_keys` → `KEY_UNKNOWN` (fail-closed). The resolver rejects a table where
`key_id` ≠ the fingerprint of its `public_key_spki_b64`, or where one `key_id` is pinned under two peers
(`ROUTE_TABLE_INVALID`, like an ambiguous locator). Ed25519 runs in `node:crypto`, so Article 17 is
satisfied. How the operator obtains F's public key out of band is Rule 47 (§4.5). The fingerprint is the
value two operators compare.

### 2.4 Exists today vs telepty#100 (Mac, task 1229)

| need | telepty `db2f532` | telepty#100 must add |
|---|---|---|
| inject id minted per delivery | yes, `daemon.js:4758` | — |
| verified session principal (sid, epoch, generation) from a bearer | yes, `daemon.js:359-379`; audit fields `inject-log.js:47-53` | — |
| session epoch on the tracked-inject record | yes, `daemon.js:679` | — |
| consumption observation per inject | yes, `GET /api/inject-observations/:id`, `daemon.js:5070` | — |
| audit read with `to`/`from` filters | yes, `daemon.js:3767-3779` | T-1: `correlation_id` filter + stored relay context |
| structured relay context on an inject | **no**: inject body destructures `prompt, no_enter, auto_submit, thread_id, reply_expected, from, reply_to, exact_target, ref_path` (`daemon.js:4745-4751`, `ref_path` at `:4790`; the route also reads `req.body.deliberation_session_id`, `:4967`); `relay_context` is not read | T-2: optional `relay_context` (§1.2 shape) stored immutably on J's record; refused unless `final_session` is J's session |
| final session posting a stage with its own bearer | **no** route | T-3: `POST /api/injects/:J/receipts {stage}` with D's bearer; refuse unless the bearer's sid+epoch = J's session+epoch |
| host identity | **self-asserted only**: `MACHINE_ID` (`daemon.js:77`), `/api/meta.host`/`machine_id` (`daemon.js:3858-3867`), audit `origin_host` (`daemon.js:4790`). No daemon key exists (searched `db2f532`: no `generateKeyPair`/`ed25519`) | T-4: host receipt key pair (Ed25519); export the public key (SPKI DER, base64) and `key_id` = `"ed25519:" + base64url(sha256(SPKI DER))` exactly; private key never leaves F |
| peer/daemon token scope | **one** token: every `/api/*` route sits behind one auth middleware (`daemon.js:395`). A peer's stored token is the target's daemon token. `POST /api/sessions/:id/kill` (`daemon.js:5279-5283`) and non-owned `DELETE /api/sessions/:id` (`:5338-5347`) need no session credential. Registering an id the daemon does not hold mints a fresh credential (`daemon.js:322-327`) | P-1 (§2.5, telepty#113 + #100): scoped peer tokens |
| signed receipt | **no**. `src/audit/provenance.js:14-21` is a nonce banner and explicitly not a signature | T-5: build + sign body §2.2 (incl. `session_guard`); serve `GET /api/requests/:C/receipts` (base §9.1 proposed) on F, and deliver/forward to O (T-6) |
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
gets nothing. Any hop to F (an agent's CLI HTTP arm today, #111's forward later) puts a token for F in
the hands of the forwarding host, and telepty#110 discloses stored peer tokens to any local-token holder
there. A channel-attested receipt could therefore be forged from the forwarding host. A signed receipt
cannot be forged without F's key (§3 I-1). The token can still squat F's sessions until P-1 holds
(RS-9). **Recommendation: signature for path S (relayed and cross-host direct); the provenance adapter
remains for path D (local direct).** This is decision D1, pending in REPORT, recommended default as
written. If the orchestrator picks channel attestation, only B5/B6 and §5's key handling change.

### 2.5 Upstream preconditions: v2 receipts stay off until these hold (BLK-2, BLK-3, BLK-4)

| id | owner / issue | exact requirement | gates |
|---|---|---|---|
| **P-1** | telepty#113 (filed by the reviewer), as a telepty#100 requirement | F issues **peer tokens distinct from its local daemon token**. A peer token authorises only `POST /api/sessions/:id/inject` (with `exact_target`, `relay_context`) and the receipt read/forward routes of T-5/T-6. It **cannot** kill, delete, rename or register any session, and cannot read `/api/peers`. F signs `session_guard:"peer-scope-v1"` only while it enforces this. (Considered and not recommended: F signs a credential-issuance time that O bounds. It depends on F's clock vs O's (RS-6), and it misses a squat registered **before** O's send while D is offline.) | every v2 receipt (B6g `F_GUARD_ABSENT`) |
| **P-2** | telepty#110 | `GET /api/peers` (`daemon.js:3921-3927` → raw `peers.json`, `cross-machine.js:401-403`) no longer returns stored tokens | operator enablement (§4.4): without it, every local-token holder on a forwarding host holds F's (scoped) peer token. Under P-1 that widens RS-1 only, not completion |
| **P-3** | telepty#100 T-1…T-7 (Mac, task 1229) | §2.4 rows, with the exact `key_id` derivation and the §2.2 body | any v2 receipt existing at all |
| **P-4** | telepty#111 | daemon-side forward for an exact remote target: returns the remote inject id + a routing receipt; forwards `relay_context` verbatim; mints no receipt for F | every cross-host telesession path (relayed R → F, and cross-host direct O → F). Until then U2 stays fail-closed |
| — | telepty#105 | cross-node alias consistency | **not** an integrity precondition (§1.2.1). It is needed only so R resolves O's intended host (availability) |

The B6g check makes P-1 machine-checked per receipt. P-2 cannot be checked from a receipt, so it is part
of the operator's enablement step (§4.4).

---

## 3. Relayer-forgery trust boundary

Adversary: any R (relaying session, its telesession, its daemon) and any carrier of receipts between F
and O, including O's own host processes **other than** O's telesession and its ledger directory. Same-uid
compromise of O's host is out of scope: such an adversary can edit O's ledger directly. R is trusted for
**what work it forwards** (the origin chose it as its delegate). R is **not** trusted for **whether F
completed it**.

Invariants (each is checkable by a reviewer and has a test row in §6):

- **I-1 (no forgery).** A receipt is applied to a path-S record only if `sig` verifies under a key
  pinned in O's peer table under O's name for `rec.destination.host` (B5, B6). R and any carrier hold no
  such key, so they cannot **produce** an acceptable receipt. T-3 MUST accept a stage post **only** with
  the destination session's own bearer, never with a peer or operator token. This is not a guarantee
  against a holder of a token for F, who can make an honest F sign for a squatted session (RS-9); P-1
  closes that. → test X1, X2.
- **I-2 (no re-targeting across requests).** C is O-minted and 128-bit random (`telepty.js:1217`). Every
  receipt must carry the record's C (B1), and the signature stops a carrier from changing it. That is
  what prevents cross-record confusion. I (B3/B4) adds liveness checks: it ties the receipt to the
  inject O knows. But R reports I itself (§1.2), so I adds no security against R (review N8). → X3.
- **I-3 (no re-targeting across endpoints).** The host is bound by the key (B5: only keys pinned for
  O's own name of the destination). `final_session` (+ epoch) is signed and must equal
  `rec.destination.session` (B7). A genuine receipt from another host, including a same-named session on
  a second host, is refused `SOURCE_MISMATCH` (its key is pinned under the other peer) or `KEY_UNKNOWN`.
  A receipt from another session on the right host is refused `SOURCE_MISMATCH`. → X4, S1, N-1.
- **I-4 (no cross-origin replay).** A receipt made for another origin's record carries that record's C
  and I. It fails B1 (C, 128-bit random, minted by each origin) before any other check. No origin host
  name is needed or compared (§1.2.1). → X5.
- **I-5 (replay / duplicate).** Applied receipt identities `(canonical(rec.destination.host), J, stage)`
  are kept on the record (`applied_receipts`, bounded 16). A second receipt with an applied identity is
  a no-op (`deduplicated`), including one re-signed with another `seq`/`at`. A byte-identical replay also
  collapses through the reply and event keys (base §7). Repeated pulls never change state. → X6.
- **I-6 (stale).** A receipt for a terminal (`rejected`) record is refused `STALE_AFTER_TERMINAL`. A
  `rejected` receipt after `origin_ack_received` is refused `REJECT_AFTER_ACK` (base §5, N14). A
  lower-stage receipt after a higher stage fills only a null timestamp. A receipt for a retired record is
  refused `RETIRED`. None of these change `stage`, `ack_seq` or `status`. → X7, X8.
- **I-7 (local direct unchanged).** A path-D record's acceptance set is exactly the `8016f25` rule
  (§1.3). → B-D1, B-D2, and the existing `e2e-full-route` direct tests unchanged.
- **I-8 (no silent weakening).** On path S a missing key, a failed signature, a v1 receipt, a missing
  `session_guard`, a missing I or an unparseable receipt each refuse with a code. None is evaluated as
  v1, as unproven, or under the provenance adapter. No path falls back to correlation-only binding
  (HOLD option C stays rejected). → B-R2, B-R3, DX2, DX3, G1.

What a compromised R **can** still do without a token for F (availability only):
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
- **RS-7 peer-token disclosure (telepty#110, current).** `GET /api/peers` (`daemon.js:3921-3927`)
  returns `listKnownPeers()`, the raw `peers.json` with stored tokens (`cross-machine.js:401-403`; the
  reviewer measured this). A compromised forwarding host, or any local process holding a local token
  there, can read the token it holds for F. With it, it can inject arbitrary work into F's sessions
  (this widens RS-1 to non-delegates on that host) and see the peer list. It cannot **produce** a
  signature (I-1). On `db2f532` it **can** squat (RS-9). P-2 closes the disclosure.
- **RS-8 agent hops H-a/H-b (today, outside telesession).** They cannot get the final inject's context to
  F (§1.4). A request relayed that way never reaches `completed` through a receipt, which is
  availability, not integrity.
- **RS-9 session-name squatting (telepty#113; review BLK-2).** On `db2f532` a holder of F's daemon token
  can complete a path-S record with no work by the real D. That holder is any forwarding host that holds
  a peer entry for F, any local-token holder there via #110, or any local-token holder on F's host. It
  (1) kills (`daemon.js:5279-5283`, no session credential) or deletes (`:5338-5347` without
  `?owned=true`) D's session `w`, or waits until D is offline; (2) registers `w` and gets a fresh bearer
  and epoch (`daemon.js:322-327`); (3) injects J′ to `w` with the (I, C) it already knows; (4) posts
  `processing_completed` with that bearer. An honest F satisfying T-3 signs. B7 passes, and B8 learns the
  new epoch (relayed records have `generation: null`, `ledger.js:497-499`). So O records `completed`
  with no real D. **Mitigation:** P-1 (§2.5) and the B6g check. A receipt from an F without
  `session_guard:"peer-scope-v1"` is refused `F_GUARD_ABSENT`, so v2 cannot complete anything until F
  scopes peer tokens. **Remains after P-1:** a holder of F's **local** daemon token on F's own host, and
  F's operator, can still squat. That is treated like F compromise (RS-3), the analogue of the
  same-uid-on-O exclusion. → X9.
- **RS-10 CLI hop forwards R's session bearer (review N2).** `fetchWithAuth` sends the caller's
  `TELEPTY_SESSION_TOKEN` to whatever daemon URL it targets (`cli.js:297-303`). An agent hop through
  the HTTP arm (H-b) therefore gives R's session bearer to F's host, which can then speak as R on R's
  daemon. This is outside telesession and not mitigated here. It is a telepty item (scope the forwarded
  header to the local daemon).
- **RS-11 interim I lookup can be jammed (review N3).** Any local-token holder on R's daemon can create
  audit rows. A row whose `verified_sender_sid` equals O's inbox needs that inbox's bearer, so with the
  §1.2(b) filter only a holder of that bearer can force `ORIGIN_INJECT_AMBIGUOUS`. A claimed `from`
  alone no longer can. The result is a refusal (availability). T-1 removes the lookup.

---

## 4. API compatibility and schema deltas

### 4.1 MCP surfaces

| surface | change | compatibility |
|---|---|---|
| `telesession_send` | none in U1. U2 adds the cross-host path, U4 the relay intake (§7) | unchanged |
| `telesession_request_status` | optional output field `receipt_refusals: {code: count}` (last pull, omitted when empty) | additive; §4.4 consumers that ignore unknown keys are unaffected |
| `telesession_read_reply` / addenda | none. A bound relayed completion is a verified reply entry, as the direct path already does (base §9.1). Its text is `[telesession receipt stage=processing_completed]\n<json>`, where the JSON adds `origin_inject_id`, `final_inject_id`, `final_session`, `key_id` (host = `rec.destination.host`, O's name) | additive keys inside the existing text format |
| `telesession_health` | none (19:27Z decision) | unchanged |
| reply entry `attestation` | a bound relayed receipt is stored with `from` = `rec.destination` → `attestation:"destination"` (existing value) | no new enum value |

### 4.2 Ledger record (base §4.1): new optional fields, `LEDGER_VERSION` stays `1`

| field | type | set by | absent / null means |
|---|---|---|---|
| `origin_inject_id` | string (`^[A-Za-z0-9._:-]{1,128}$`) \| null | `openLedgerRecord` at create (I; for a cross-host direct record, the remote inject id = J); reconstructed records: the store's `inject_id` | unknown: path-S receipts refused `INJECT_UNKNOWN`; path D falls back to the store inject (today) |
| `applied_receipts` | list of 64-hex (sha256 of `canonical(rec.destination.host)/J/stage`), bounded 16 | applying a path-S v2 receipt | empty |

(`applied_receipts` was `receipt_keys` in revision 1. It is renamed so that `receipt_keys` names only the
per-peer pinned public keys of §2.3, review N5.)

Why no version bump: `isRecord` (`ledger.js:90-99`) checks named fields and does not reject extra keys.
`commit` deep-copies state with `structuredClone` (`ledger.js:297`), which keeps unknown keys. So an
`8016f25` build opens and rewrites a ledger written by U1 code without loss. Bumping `LEDGER_VERSION`
would make that older build refuse the file (`LEDGER_VERSION_UNSUPPORTED`, `ledger.js:283`) and break
rollback. U1 code MUST validate both fields when present (shape and bound), so a tampered value is
`LEDGER_CORRUPT` as for other fields. The store schema is **not** touched: `STORE_VERSION` and its
exact-key check (`store.js:52-55`) stay as they are.
Byte margin: `origin_inject_id` adds at most about 160 B to a record at create. The test-measured worst
case of 5669 B (`ledger.js:50`) stays under `RECORD_MARGIN_BYTES` 8192. `applied_receipts` is written
after create, outside the reserved margin, and counts toward the 4 MiB bound like `events`.

### 4.3 Receipt schema versions (by path, §1.3)

| receipt | path D (local direct) | path S (relayed, or cross-host direct) |
|---|---|---|
| v1 (base §9.1, today): no `v`, no `sig` | `8016f25` rule, unchanged | refused `SIGNATURE_REQUIRED` |
| v2 (§2.2): `v:2`, signed body, `sig`, `inject_id` = J | `8016f25` rule on `inject_id`; v2 fields ignored, signature not evaluated (path D never used one) | B0–B9. Signature mandatory: no key pinned → `KEY_UNKNOWN`, bad signature → `SIGNATURE_INVALID`. Refused, no state change, no marker, no v1 fallback |

There is no "treat as v1" case anywhere (revision 1's unpinned-key downgrade is removed, review BLK-3).
The cross-host direct record exists only once telepty#111 lands (P-4). Until then path S holds relayed
records only.

### 4.4 Migration and rollback

- Forward: no migration step. Records created before U1 have no `origin_inject_id`. Direct ones keep
  binding through the store inject (until it is purged, as today). Relayed ones keep being refused
  (`SIGNATURE_REQUIRED` for v1, `INJECT_UNKNOWN` for v2), and their completion stays reachable only
  through the leg-1 addendum path.
- Rollback to `8016f25`: revert the U1 commits. The ledger opens unchanged (§4.2), and the extra fields
  are carried along unread. Relayed receipts go back to `INJECT_MISMATCH`. Records already `completed`
  through a bound relayed receipt stay `completed`: their reply entry and stages are ordinary fields.
- Nothing changes live by default. The default receipt adapter stays `NO_RECEIPTS` and the peer table has
  no `receipt_keys`, so every v2 path is inert until an operator pins keys and enables a receipt adapter.
  Enabling either is a separate approval (base §10 activation rule). That approval requires P-1…P-4
  (§2.5) to be met on the telepty build in use. P-1 is also checked per receipt (B6g); P-2 is checked only
  at approval. Until then **v2 stays off**.

### 4.5 Rule 47 items (cited, not decided)

| item | recommended default |
|---|---|
| storage of F's private key (telepty) | F's data dir, file 0600, generated on first start, never exported; public key exportable |
| pinning store for `receipt_keys` (telesession) | the operator-supplied peer table (same source as the resolver), read-only to telesession, no TOFU |
| key rotation / revocation | a list of `key_id`s per peer; removing a key_id revokes it; receipts under it → `KEY_UNKNOWN` |
| retention of `applied_receipts` / refusals | lives and retires with the record (7 days, base §6.1) |
| auth scope of `POST /api/injects/:J/receipts` | D's own bearer only; no operator or peer token |
| peer-token scope on F (P-1) | inject + receipt routes only; no kill/delete/rename/register, no `/api/peers` |
| out-of-band exchange of F's public key | operator copies the SPKI and compares the `key_id` fingerprint on both ends |

---

## 5. Synthetic fixture contract (`test/helpers/fake-receipts.js`, `test/helpers/fake-telepty.js`)

The fixture stands in for telepty#100 T-1…T-7 on F. It MUST NOT be taken as evidence that those exist.

**Keys.** `createFakeReceiptSeam({mode, selfLabel, keys, guard = "peer-scope-v1"})`: when `keys` is
absent, the seam calls `generateKeyPairSync("ed25519")` once per seam instance, **in the test process**.
Keys are never written to disk, never read from the environment or the filesystem, and never shared
across seams. `key_id` is the §2.2 fingerprint. The seam exports only `keyId()` and
`publicPeerEntry(peerIdAtO, locatorsAtO)` → `{peer_id: peerIdAtO, locators: locatorsAtO,
receipt_keys:[{key_id, public_key_spki_b64}]}` for O's peer table. **O's name is a parameter, never the
seam's own label.** It also exports a second synthetic key pair (`otherKeys`) for forgery cases. No
helper accepts or emits a real key. A test-runner guard asserts that no file under the sandbox contains
the PEM header `PRIVATE KEY`.

**Distinct names (BLK-1).** Every relayed fixture uses three different strings for the same F: O's peer
id (e.g. `mac`), R's peer id (e.g. `macbook`), and F's `selfLabel` (e.g. `host-m`). O itself is `local`
at O and `kkoma` in R's table. A helper that uses one string for two of these roles is a fixture bug. The
fixture asserts that the three strings differ.

**Minting.** `finalDaemon({sid, epoch})`:
- `send(item)`: as today (`fake-receipts.js:37-44`), plus it reads `item.relay_context` (or
  `envelope.relay_context` for the JSON-envelope path). It refuses `RELAY_CONTEXT_INVALID` unless the
  context is well-formed (§1.2 shape) with `final_session === sid`. It does **not** check any host name.
  It mints J = `randomUUID()` and stores `{J, relay_context, session: sid, epoch,
  delivered_payload_sha256}` immutably.
- `attest(J, stage, opts)`: builds the §2.2 body from the stored J record (never from caller input),
  sets `session_guard` from the seam's `guard` (`null` models an F without P-1), sets `inject_id = J`, and
  signs with the seam key. `seq` is per J.
- `observe(...)` unchanged.
- `squat({sid, prompt, relay_context})` (X9): models RS-9 on an F **without** P-1. It re-registers `sid`
  with a fresh epoch, mints J′ with the copied context and returns J′. Then `attest(J′, …)` signs as an
  honest F would. With `guard:"peer-scope-v1"` the seam refuses `squat` (`PEER_SCOPE_DENIED`), modelling
  P-1.

**Adversarial producers** (each returns a receipt object; none mutates stored state):

| helper | produces | expected at O |
|---|---|---|
| `forge(J, stage, {key: otherKeys})` | valid body signed with an unpinned key | `KEY_UNKNOWN` (unknown `key_id`) or `SIGNATURE_INVALID` (pinned `key_id`, wrong key) |
| `tamper(receipt, field, value)` | the signed receipt with one body field changed after signing (relayer modification) | `SIGNATURE_INVALID` |
| `retarget(receipt, {origin_inject_id \| correlation_id \| final_session})` | re-signed with the **seam** key (a genuine F signing a different fact) | `INJECT_MISMATCH` / `CORRELATION_MISMATCH` / `SOURCE_MISMATCH` |
| `replay(receipt)` | the same object posted again | `deduplicated`, no state change |
| `resign(receipt, {seq, at})` | same identity, new seq/at, valid signature | `deduplicated` (I-5) |
| `stale(J, stage)` | a valid receipt posted after the record became terminal or retired | `STALE_AFTER_TERMINAL` (direct `applyReceipts` call only, N4) / `RETIRED` |
| `unsigned(J, stage)` | v1 shape (no `v`, no `sig`) for a path-S record | `SIGNATURE_REQUIRED` |

**`fake-telepty.js`** (models the daemon O and R inject into): adds `relay_context` passthrough on
`POST /api/sessions/:id/inject` and stores it on the audit row. It adds the `correlation_id` filter on
`/api/injects` (T-1). Audit rows carry `verified_sender_sid` (for the §1.2(b) filter) and a test hook
plants an unverified row with a claimed `from` (RS-11). It advertises `final-receipts-v2` only when
constructed with `{receiptsV2:true}` (capability absent by default, as on `db2f532`). `{forward111:true}`
adds a fake #111: an inject to `sid@<peer>` is forwarded to the seam F registered for that peer **in
this fake daemon's own table**. It returns J + a routing receipt and passes `relay_context` verbatim, or
strips/rewrites it under `{forward111:"strip"|"rewrite"}` (H3). Existing facts F1–F5
(`fake-telepty.js:1-25`) are unchanged.

---

## 6. Test matrix

Unit / isolated rows (U1, U5) live in `test/e2e-full-route.test.js` and `test/relay-receipt-binding.test.js`
(new). The latter must be added to the test-runners guard list.

| id | case | setup | expected |
|---|---|---|---|
| B-D1 | binding success, direct | direct send; v1 proven receipts naming `s.inject_id` | `origin_ack_received` → `completed` after the checkpoint (existing test, unchanged) |
| B-D2 | direct after store purge | as B-D1, store record purged (clock past the store retain), ledger live | still bound through `rec.origin_inject_id` (fails on `8016f25`: `INJECT_UNKNOWN`) |
| B-R1 | binding success, relayed | O → R (fake-telepty) → R relay runner with relay_context {C, I} → fake #111 → seam F; distinct names (O calls F `mac`, R calls F `macbook`, F's label `host-m`); F signs `agent_consumed`, `processing_completed` | `applied 2`; stage `origin_ack_received`; reply `attestation:"destination"`, body names I + J; `completed` after the checkpoint |
| B-R2 | relayed, no pinned key | as B-R1, peer table without `receipt_keys` | `KEY_UNKNOWN ×2`; pending; no marker; never evaluated as v1 (I-8) |
| B-R3 | relayed, legacy v1 receipt | `unsigned()` | `SIGNATURE_REQUIRED`; pending |
| N-1 | names differ at every node (BLK-1) | as B-R1, plus R's table names O `kkoma` and F `macbook`; F's `selfLabel` `host-m`; none of the strings appear in O's table except O's own `mac` | `completed`. The receipt body contains no host name. Control: pin the key under a **different** O peer (`linux`) instead of `mac` → `SOURCE_MISMATCH` |
| N-2 | R misroutes to another daemon G (R's table maps `macbook` to G, which also has a session `w`) | G is a second seam whose key is pinned at O under `linux` | `SOURCE_MISMATCH`; pending; F's genuine receipt (once routed right) still binds |
| N-3 | key_id / fingerprint mismatch in O's table | `receipt_keys` entry whose `key_id` ≠ fingerprint of its SPKI; and one `key_id` under two peers | resolver throws `ROUTE_TABLE_INVALID` at construction; no receipt evaluated |
| X1 | forged by relayer | `forge(..., otherKeys)` | `KEY_UNKNOWN` or `SIGNATURE_INVALID`; status unchanged |
| X2 | relayer-modified | `tamper(r, "stage", "processing_completed")` on an `agent_consumed` receipt | `SIGNATURE_INVALID` |
| X3 | re-targeted to another request | two O records; F's receipt for record 1 presented under record 2's correlation; `retarget` with record 2's I | `CORRELATION_MISMATCH` / `INJECT_MISMATCH`; record 2 unchanged |
| X4 | re-targeted endpoint | `retarget(final_session)`; and a genuine receipt from another pinned host (S1) | `SOURCE_MISMATCH` |
| X5 | cross-origin replay | a genuine F receipt for **another origin's** record (its own C and I) fetched into O's pull | `CORRELATION_MISMATCH`; no host name involved |
| X6 | replayed / duplicate | `replay`, `resign`, two pulls | `deduplicated`; one reply, one seq; `ack_seq` unchanged |
| X7 | stale after terminal | F `rejected` applied, then `processing_completed`, through a **direct `applyReceipts` call** (the status path returns early for a terminal record, `telepty.js:1413`, N4) | `STALE_AFTER_TERMINAL`; status `rejected`. Status-path control: `request_status` makes no pull and has no `receipt_refusals` entry |
| X8 | rejected after ACK / retired | `processing_completed` then `rejected`; record past `retain_until` | `REJECT_AFTER_ACK`; `RETIRED`; `completed` stays |
| X9 | session-name squatting (RS-9, BLK-2) | seam with `guard:null`: `squat({sid:"w"})` with the copied (I, C), then `attest(J′, "processing_completed")`. Then the same with `guard:"peer-scope-v1"` | `guard:null` → `F_GUARD_ABSENT`, pending, not completed (v2 off without P-1). `peer-scope-v1` → `squat` refused `PEER_SCOPE_DENIED` at the seam, no J′; the real D's receipt completes |
| G1 | F without P-1, honest flow | B-R1 with `guard:null` | `F_GUARD_ABSENT ×2`; pending (I-8) |
| DX1 | cross-host direct (#111; BLK-3) | O sends `w@mac` through fake #111 on O's daemon; `rec.via === null`, `destination.host === "mac"`, `origin_inject_id` = returned J; seam signs with `origin_inject_id:null` | path S; B4d passes; `completed` after the checkpoint; the provenance adapter is not called |
| DX2 | cross-host direct, no pinned key / v1 / bad signature | as DX1 with no `receipt_keys`; then `unsigned()`; then `tamper()` | `KEY_UNKNOWN`; `SIGNATURE_REQUIRED`; `SIGNATURE_INVALID`. Each: no state change, no `REMOTE_PROVENANCE_UNAVAILABLE` marker |
| DX3 | cross-host direct, receipt names another J | seam receipt for J2 ≠ `rec.origin_inject_id` | `INJECT_MISMATCH` |
| DX4 | local direct with a v2 receipt (path D) | B-D1, but the fake returns v2 receipts (with `inject_id` = `s.inject_id`) | the `8016f25` outcome exactly (as B-D1); `sig` not evaluated |
| S1 | same-name target, two hosts | O's table `peer-a`, `peer-b`, both with session `w` and both pinned; destination `peer-b/w`; a genuine `peer-a/w` receipt naming the same I + C | `SOURCE_MISMATCH` (B5: key pinned under the other peer); the `peer-b/w` receipt applies. U2 repeats this on the real send path once #111 exists (U6 harness) |
| L1 | I lookup ambiguous at R | two verified leg-1 injects from the same inbox to R in one window, interim lookup | `ORIGIN_INJECT_AMBIGUOUS` at R; O refuses `INJECT_UNKNOWN`; not completed |
| L3 | I lookup spoof attempt (RS-11, N3) | one genuine verified row + one planted row with `claimed_from` = O's inbox and no verified sender | the planted row is ignored; I = the genuine inject id; `completed` |
| L2 | hop limit | relay_context `hop:4` re-relayed | `RELAY_HOP_LIMIT`, outbox `failed` |
| RS1 | re-send after transport failure | R's first relay send `sent:"no"` (fake refuses once) → requeued → sent (J2) | one J applied; O completes; outbox attempts 2 |
| RS2 | re-send creating two J | R forwards twice (operator re-enqueue) → J1, J2 both complete | first completion sets `first_ack_seq`; J2 moves `ack_seq` forward, `NEWER_FINAL_ACK_UNREAD`; no duplicate seq |
| RC1 | origin restart mid-flow | reopen O's ledger and transport between the relay send and F's receipts | receipts bind after reopen (I persisted in the ledger); seq/cursor continue |
| RC2 | daemon restart (RC5-style, real daemon) | U4: real telepty from `TELESESSION_TEST_TELEPTY_DIR`; leg-1 inject accepted; daemon restarted on the same HOME and port; relay continues | I and C unchanged; the wrapped R keeps its epoch; O completes from F's signed receipt. Gated as the real-daemon set (docs/ci.md), never the operational daemon |
| C1 | compat | 8016f25 ledger fixture opened by U1 code; U1 ledger opened by the 8016f25 `isRecord` | both open; fields preserved; no version error |
| H1 | agent hops H-a/H-b (no relay_context at F) | R's **agent** forwards without relay_context (SSH-like: no J; HTTP-like: J printed to the agent only); F mints J without context | F can produce no v2 receipt for J; any receipt for J is refused (`INJECT_MISMATCH`, or `SIGNATURE_REQUIRED` for v1); O stays pending, then unknown; a leg-1 addendum still arrives as `relayed_by_leg1_destination` |
| H2 | #111 routing receipt is hop evidence only | B-R1 through the fake #111 | the routing receipt maps only to R's leg `transport_accepted`, never to a destination stage at O |
| H3 | #111 drops or rewrites relay_context | `{forward111:"strip"}` / `{forward111:"rewrite"}` (changes `origin_inject_id`) | stripped: F refuses `RELAY_CONTEXT_INVALID` or signs no v2 receipt → pending; rewritten: `INJECT_MISMATCH`; never completed |
| H4 | telesession never posts to a remote daemon (BLK-4) | O and R transports with a non-local destination and no fake #111 | `PEER_UNSUPPORTED`/`PEER_UNKNOWN` (U2 behaviour); zero HTTP requests to any port other than the local fake daemon |

**U6 two-daemon isolated E2E harness (design).** All harness processes are started and stopped by the
test. The operational daemon is never touched.
- Two telepty daemons from `TELESESSION_TEST_TELEPTY_DIR` through `startRestartableTeleptyDaemon`
  (`test/helpers.js:294-316`). Each has its own temp `HOME` (data dir, credential store, audit), its own
  `PORT` (0 → bound port read back) and its own `TELEPTY_MACHINE_ID` (`host-k`, `host-m`). The labels are
  self-asserted and appear in **no** peer table. K-side's table names M `mac`, and the relayer stub's
  routing table names M `macbook` (BLK-1: distinct names per node, as row N-1).
- Two telesession endpoints (transports with their own state dirs and ledgers). **K-side** (origin) points
  at daemon `host-k`. **M-side** points at daemon `host-m`. A relaying R (an "L" stub session) is
  registered on `host-k` for the via case.
- **The cross-host hop is a test-only stand-in for telepty#111 (P-4), not a production path.** No
  daemon forwards across hosts (§1.4), telesession never posts to a remote daemon (BLK-4, U2 fork 3
  rejected), and nothing in `src/` gains a remote-post code path. The **harness forward shim** lives in
  the test process and plays #111 for `host-k`. It receives the forward request that R's (or, for case
  (a), O's) transport would hand to #111. It injects into daemon `host-m` with `exact_target:true`, and
  returns `{inject_id: J, routing_receipt}` to the caller. It holds `relay_context` in memory for the
  receipt shim (below), because the real `host-m` does not read it (`daemon.js:4745-4751`).
  - To post into `host-m`, the shim uses a synthetic token: `randomBytes(32)` minted in the test, set as
    daemon `host-m`'s `TELEPTY_AUTH_TOKEN` in that daemon's env, held only in the test process's memory,
    never logged, never written to any file (no `peers.json` entry is written), and discarded at
    teardown. The real `~/.telepty/peers.json` and any real token are never read: the harness asserts
    that `HOME` points into its temp dir before it starts anything. The CLI is not driven.
  - It is named "harness #111 shim" in the test output. Once telepty#111 lands, it is removed and the
    rows run against the real forward (an inject to `w@<peer>` on `host-k`).
  - The transport reaches the shim only through the #111 client seam that U2 adds once #111's contract
    exists: an injected `extensions.forward`, absent by default, which means U2's fail-closed
    `PEER_UNSUPPORTED`/`PEER_UNKNOWN`. Until U2 adds that seam, cases (a)–(e) report `NOTRUN` (reason:
    `no #111 client`), never pass.
- Stubs are wrapped sessions spawned from test-support children, as RC5 does. The **Kkoma stub** is O's
  origin agent (it calls send/request_status). The **Mac stub** is D on `host-m`: it reads its prompt and
  posts stage facts with its own bearer.
- F in the harness: until telepty#100 exists, a **harness receipt shim** in the test process plays T-2…T-6
  for `host-m`. The daemon keeps only a verifier of each bearer (`daemon.js:329-331`), so the shim cannot
  check a bearer itself (review N7). Instead, at setup the shim registers its **own** session `rx` on
  `host-m`. The Mac stub posts a stage fact as an **inject to `rx`** with its own bearer, with the body
  `{"telesession_stage":{"J":…,"stage":…}}`. `host-m` authenticates that inject and writes the audit row
  with `verified_sender_sid` + `verified_sender_epoch` (`inject-log.js:47-53`). The shim reads
  `GET /api/injects?to=rx` and accepts a stage only from a row whose verified sid + epoch equal J's
  recorded session + epoch (J's epoch from the forward response / `daemon.js:679`). It then signs with a
  synthetic key, with `session_guard` per case, and serves receipts to K-side's receipt adapter. The
  shim is named as such in the test output. Once telepty#100 lands, it is removed and the same rows run
  against the real T-routes.
- Cases: (a) cross-host direct K → M through the #111 shim (DX1); (b) via K → L → M; (c) same-name `w`
  on both daemons, destination `mac/w`; (d) X1/X3/X6/X9 on the real wire (X7 by direct `applyReceipts`
  only, N4); (e) `host-m` restart between delivery and the Mac stub's post (RC2); (f) H1 (agent hop
  without relay_context): stays pending, never completed.
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
2. **`src/relay/route.js`** (about 25 lines): accept optional `receipt_keys` per peer (validated:
   `key_id` `^ed25519:[A-Za-z0-9_-]{43}$` and equal to the fingerprint of its SPKI, SPKI base64 ≤ 128
   chars, ≤ 4 per peer, no `key_id` under two peers); `receiptKeys(peerId)` → map, and
   `peerOfKey(key_id)` for B5's `SOURCE_MISMATCH` case. Existing resolver behaviour is unchanged.
3. **`src/relay/ledger.js`** (about 40 lines): `createRequest` accepts `origin_inject_id`. `isRecord`
   validates `origin_inject_id` and `applied_receipts` when present. New `noteReceipt(nonce,
   identitySha)`, or `receipt_identity` on `recordEvent`, appends to `applied_receipts` (bounded 16)
   **in the same commit** as the event. `recordEvent` returns `deduplicated` when the identity is present.
   `LEDGER_VERSION` is unchanged.
4. **`src/relay/adapters.js`** (about 70 lines): `isReceiptV2(r)` (on top of `isReceipt`). `applyReceipts`
   gains a `pinnedKeys` resolver (`receiptKeys`, `peerOfKey`) and a `localPeer` (`"local"`). Path S
   (`rec.via !== null` or `rec.destination.host !== localPeer`) → B0–B9 (v1 → `SIGNATURE_REQUIRED`;
   `session_guard` check B6g; no provenance call). Path D → today's code path untouched (I-7). A terminal
   record → `STALE_AFTER_TERMINAL` before the ledger call. The stored reply JSON adds the §4.1 keys.
5. **`src/transports/telepty.js`** (about 25 lines): `openLedgerRecord` passes `origin_inject_id:
   b.inject_id`. `reconcileLedger` passes `q.inject_id`. `pullReceipts` uses `lr.origin_inject_id ??
   q.inject_id` for the known set, and passes `pinnedKeys` from the configured resolver and
   `localPeer: LOCAL`. `requestStatus` attaches `receipt_refusals` from the last pull. No remote-post
   code path is added (BLK-4).
6. **`test/helpers/fake-receipts.js` / `fake-telepty.js`**: §5. **Tests**: §6 rows B-*, N-*, X*, G1,
   DX1–DX4 (with the fake #111 in `fake-telepty.js`, which tests `applyReceipts` path S on a
   destination ≠ local record; the transport-level DX run is U2), S1, L2, H4, RC1, C1 (U1). L1, L3, RS1,
   RS2, RC2 are U4. U6 is the harness.
7. **Spec/CHANGELOG**: base §9.1 pointer (done in this commit). Add a CHANGELOG entry under the next
   release.

Size: about 250 lines of `src/` and about 450 lines of tests and fixtures. That is 2 coder loops + 1
review (plan §3 estimate holds).

**What later units need from this spec:**
- U2 (cross-host send): no daemon forward exists (§1.4). Until telepty#111 lands (P-4), the telesession
  cross-host path stays **fail-closed**, as U2 shipped it (fork 1; fork 3, a direct remote post with a
  peer token, is rejected). There is no interim telesession path. The interim hop that exists is an
  agent's CLI (H-a/H-b, outside telesession), and it cannot produce a v2 receipt (RS-8). After #111: add
  the `extensions.forward` client behind a capability check. R's runner (relayed) or O's send (cross-host
  direct, I = J) injects through its own daemon with `relay_context`, with no change to O's binding. Run
  S1, DX1–DX3 and H1–H4 on the real send path.
- U3 (real adapter, after telepty#100): implement T-1…T-7 consumers. Remove the U6 shim. Ensure v2 field
  names and the signature domain match §2.2 exactly.
- U4 (re-send/recovery + relay intake): R-side I lookup (§1.2 a/b, `ORIGIN_INJECT_AMBIGUOUS`), the
  verbatim relay_context copy, `RELAY_HOP_LIMIT`, rows L1, RS1, RS2, RC2.
- U5 (forged/stale/duplicate E2E): rows X1–X9 on the U6 harness.
- U6: §6 harness design.
- Enabling v2 anywhere: the operator approval of §4.4, after P-1…P-4 (§2.5).

## 8. Open decisions (pending, with recommendation)

- **D1** signature (recommended) vs channel attestation for path-S receipts (§2.4 note).
- **D4** BLK-2 remedy: scoped peer tokens signed as `session_guard` (P-1, recommended) vs an F-signed
  credential-issuance time bounded by O (rejected in §2.5: clock-dependent, and misses a pre-send
  squat). Either way v2 stays off until telepty ships it.
- **D2** the interim I lookup (§1.2 b) vs waiting for telepty#100 T-1. Recommended: ship (b). It fails
  closed on ambiguity.
- **D3** Rule 47 items in §4.5 (recommended defaults listed).
