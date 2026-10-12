REPORT: ts-1110-u1 task #2026101110 — U1 PROTOCOL SPEC — DONE

files:
  - docs/specs/2026-10-12-relayed-receipt-binding.md (new companion spec)
  - docs/specs/2026-10-11-e2e-delivery-protocol.md (§9.1: 3-line pointer added; nothing else changed)
  - REPORT.md (this file; stands in for the REPORT inject because telepty is not on PATH in the sandbox)

commits: on task-1110-u1-protocol, not pushed. Run `git log -1` for the sha: docs(2026101110): specify the relayed-receipt binding protocol (U1, #8)

binding_rule:
  - Relayed records are fail-closed, checked in order B0–B9 (§1.3):
    - B1 correlation_id matches the record
    - B2 the receipt is role final with an own_bearer basis
    - B3 the record's origin_inject_id is known, otherwise INJECT_UNKNOWN
    - B4 the receipt's origin_inject_id matches it, otherwise INJECT_MISMATCH
    - B5 origin_host is this origin, otherwise ORIGIN_MISMATCH
    - B6 the signature verifies under the key pinned for final_host, otherwise KEY_UNKNOWN / SIGNATURE_INVALID
    - B7 final_host + final_session + epoch equal the record's destination, otherwise SOURCE_MISMATCH
    - B8 the ledger's stage rules, with STALE_AFTER_TERMINAL for a terminal record
    - B9 dedupe on (final_host, J, stage)
  - Refusals are counted in the per-pull applyReceipts result and in the optional status field receipt_refusals (last pull only). There is no health counter, per the 19:27Z decision.
  - Direct records keep the 8016f25 rule unchanged.
  - A v1 receipt without origin_inject_id gets today's behaviour: direct is bound; relayed is refused.

signing_party:
  - The final daemon F signs; D and hops do not.
  - J is minted by F. D posts its stage facts to F with its own bearer, and F checks that bearer's sid + epoch against J's record.
  - Ed25519 (node:crypto) over "telepty-final-receipt/v1\n" + canonical JSON of these fields:
    v, correlation_id, origin_inject_id, origin_host, final_inject_id, final_host, final_session, final_session_epoch, stage, seq, at, attested_by{sid,epoch,generation}, delivered_payload_sha256, key_id.
  - The origin verifies with a pinned public key from its peer table (receipt_keys). No TOFU.
  - Not verifiable until telepty#100 T-1…T-7 land. The synthetic fixture (§5) models F.

trust_boundary:
  invariants:
    - I-1 no forgery without a pinned key
    - I-2 no re-targeting across requests (I and C are signed and must hit the same record)
    - I-3 no re-targeting across endpoints (host/session/epoch are signed; covers the same-name session on two hosts)
    - I-4 no cross-origin replay (origin_host is signed)
    - I-5 replay/duplicate is a no-op (receipt_keys identity)
    - I-6 stale after terminal, reject after ACK, or retired: no state change
    - I-7 the direct rule is unchanged
    - I-8 no silent fallback to correlation-only binding
  hop_model (§1.4, folded in from the orchestrator note / U2 coder measurement):
    - No daemon-side cross-host inject exists today; the CLI does the hop (SSH arm / HTTP arm).
    - H-a SSH arm: no J, no relay_context. It is unbindable, so the request stays pending/unknown.
    - H-b HTTP arm: J comes back in the response; relay_context goes in the body.
    - H-c telepty#111: must forward relay_context verbatim and return J + a routing receipt. The routing receipt is hop evidence only.
    - Binding is hop-mode independent: it depends only on F's signed receipt.
  a compromised relayer can (availability only): drop, delay, duplicate-forward, or mislabel → the request stays pending/unknown, never a false completion.
  residuals:
    - RS-1 substitution: the relayer forwards different work under the origin's (I, C)
    - RS-2 delivered hash is not compared
    - RS-3 F's key compromised
    - RS-4 D lies about completion
    - RS-5 a destination session re-created after the first receipt → GENERATION_MISMATCH
    - RS-6 the receipt clock is never used for acceptance
    - RS-7 telepty#110: GET /api/peers discloses peer tokens to local-token holders. A compromised leg-1 host can inject into F (this widens RS-1) but cannot forge a receipt: no signing key, and T-3 accepts only D's bearer. This strengthens D1 against channel attestation.
    - RS-8 the H-a hop cannot prove a final inject exists

api_compat:
  - MCP tools are unchanged except the optional request_status field receipt_refusals.
  - Ledger record gains two optional fields: origin_inject_id and receipt_keys (bounded 16). LEDGER_VERSION stays 1.
    - Reason: isRecord does not reject extra keys and commit's structuredClone keeps them (ledger.js:90-99, :297).
    - A version bump would make 8016f25 refuse the file (ledger.js:283) and break rollback.
  - Store schema untouched.
  - Receipt schema v1 vs v2 is documented (§4.3).
  - Rollback = revert the U1 commits. The ledger opens as-is and the extra fields are carried along unread.
  - Inert by default: NO_RECEIPTS and no pinned keys.

fixture_contract:
  - Ed25519 key pairs generated in the test process per seam instance; never persisted or read from the environment; plus a second synthetic pair for forgery.
  - The fake final daemon stores relay_context per minted J and builds every signed body from its stored J record.
  - Adversarial producers: forge, tamper, retarget, replay, resign, stale, unsigned — each with its expected refusal code.
  - fake-telepty adds relay_context passthrough, a correlation_id audit filter, and a capability flag that is off by default.

test_rows:
  - binding: B-D1, B-D2 (direct after store purge), B-R1, B-R2, B-R3
  - forgery/stale/duplicate: X1–X8
  - same-name peer: S1
  - I lookup and hop limit: L1, L2
  - re-send: RS1, RS2
  - recovery: RC1, RC2 (RC5-style real daemon)
  - compat: C1
  - hop modes: H1 (H-a stays pending), H2 (H-b and H-c give the same outcome at O), H3 (#111 drops or rewrites relay_context → refused)
  - U6 harness design:
    - two telepty daemons via startRestartableTeleptyDaemon, each with its own HOME, PORT and TELEPTY_MACHINE_ID
    - K-side and M-side telesession endpoints
    - Kkoma and Mac stubs as wrapped sessions
    - the cross-host hop is driven by a stub leg-1 relayer that posts over the HTTP arm directly to daemon B, using a test-only peer entry in the temp HOME. Its token is synthetic: randomBytes, set as daemon B's TELEPTY_AUTH_TOKEN, in-test only. The harness asserts HOME is temp, so the real peers.json is never read.
    - a named harness receipt shim for F until telepty#100 lands
    - cases: direct, via, same-name, adversarial, restart, H1
    - never the operational daemon

impl_plan: §7, in order:
  1. src/relay/receipt-sig.js (new, about 50 lines)
  2. route.js receipt_keys (about 20)
  3. ledger.js optional fields + receipt identity dedupe (about 40)
  4. adapters.js v2 relayed path, direct path untouched (about 60)
  5. telepty.js persist and use origin_inject_id, pinned keys, receipt_refusals (about 25)
  6. fixtures + tests
  7. CHANGELOG
  Size: about 250 lines of src and about 450 lines of test; 2 coder loops + 1 review.
  What U2/U3/U4/U5/U6 need is listed in §7.

telepty_measured (db2f532, read from source, not run):
  - inject id minted at daemon.js:4758
  - verified principal from a bearer at daemon.js:359-379, session-credentials.js:84
  - session_epoch on the tracked-inject record at daemon.js:679
  - GET /api/inject-observations/:id at daemon.js:5070
  - GET /api/injects with to/from filters at daemon.js:3767-3779
  - audit row fields (verified_sender_*, origin_host, payload_sha256 of the raw prompt) at inject-log.js:43-60
  - inject body reads no relay context (daemon.js:4745-4751)
  - host identity is self-asserted only: MACHINE_ID (daemon.js:77), /api/meta (daemon.js:3858-3867), audit origin_host (daemon.js:4790)
  - provenance banner is a nonce, explicitly not a signature: provenance.js:14-21
  - SSH remoteInject returns no remote inject id: cross-machine.js:329-348
  - the inject route resolves the local session table only: daemon.js:4742-4746 (re-read by me)
  - measured by the U2 coder, cited and not re-measured: bus @host stripping (daemon.js around 3430 / 5433); the CLI HTTP arm (cross-machine.js:443-509, cli.js around 3483-3548); telepty#110 peer-token disclosure
  - No host signing key, no receipt route, no verified_sender_host, no receipt capability.

telesession_measured (8016f25, source):
  - store retains a request for TTL + 1 day (store.js:23, telepty.js:1226); ledger retains it for 7 days (ledger.js:23).
  - pullReceipts reads the inject from the store (telepty.js:1416-1418).
  - Consequence: a direct receipt is refused INJECT_UNKNOWN between day 1 and day 7. This is a pre-existing gap. Persisting origin_inject_id in the ledger fixes it; row B-D2 will prove it failing-first.

not_measured:
  - nothing was run; this was a spec-only dispatch, and no tests were run because none changed
  - no live daemon, no second host, no real key
  - whether the telepty inject route rejects unknown body keys (read: it does not read them)
  - whether /api/injects `from` matches claimed or verified sender on the real daemon (fake-telepty F5 says both)
  - macOS/Windows

decisions_pending (recommended default stated in the spec; not blocking U1 code):
  - D1 Ed25519 signature (recommended) vs channel attestation for relayed receipts. The spec includes a constitutional note on Art.1 and telepty's provenance "watched line": verification is done by code, not by an LLM.
  - D2 interim I lookup from R's audit (recommended; it fails closed on ambiguity) vs waiting for telepty#100 T-1.
  - D3 Rule 47 items (key storage, pinning store, rotation, retention, receipt-post auth scope): defaults in §4.5.

snyk: NOT_APPLICABLE_DOCS (the dispatch also notes Snyk is UNAVAILABLE_ON_HOST)

blockers: none for U1 code. U3 and the real T-routes depend on telepty#100 / Mac 1229 (ETA unknown, Mac-owned). The REPORT inject cannot be sent: telepty is not on PATH in the sandbox, so this file stands in.
