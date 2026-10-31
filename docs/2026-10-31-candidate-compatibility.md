# Telepty candidate compatibility and uncertainty repair

Consumer baseline: 90d88aa212d73a5fba3862da17e76310e5b13c98. Work is isolated in
`telesession-candidate-compat-20261031`, branch `fix/telepty-uncertain-http`.
Original checkout and installed runtime are untouched. Runtime dependencies are
borrowed through a local symlink; no install or external request was performed.
Test-selected Telepty: `/home/duckyoung-kim/Documents/Codex/2026-10-29/task/telepty-issues-128-135`,
source commit b842f0c5044b938977d5c64358ab6f7c8042dc43.

## Reproduced and repaired

The unmodified consumer real-daemon suite passed eight cases and failed its ninth:
it expected receiver503 to return200 and retry, whereas the candidate returns502
unknown, preserves payload and refuses automatic replay. No Telepty guard was
weakened to satisfy that obsolete expectation.

Two actual consumer defects were then reproduced:

1. Inject non-2xx responses were all classified as known refusal. A502 body with
   delivery_uncertain:true was persisted/reflected as accepted:false/state:refused.
   Inject HTTP5xx or explicit delivery uncertainty now enters the existing uncertain
   state, with no automatic replay. Known403 rejection and registration/delete
   classification are unchanged; no new trust or protocol permission is added.
2. Durable audit recovery mapped any verified failed:* row to refused, including
   the real candidate's failed:DELIVERY_UNCERTAIN. The actual503 close/reopen test
   failed with refused instead of uncertain. Attribution alone cannot prove zero
   effect; failed:* now remains unverified/uncertain. Success/queued acceptance and
   explicit blocked refusal retain their existing handling.

Seven regressions cover500/502/503, explicit uncertainty on409, known403, stable
request-ID/no-resend and durable reopening, including an actual private candidate
endpoint receiving bytes then503. Unknown payload remains in the candidate's DLQ;
the receiver-full test frees space, waits and confirms no retry or second effect.

## Verification

Final consumer `npm test`, with explicit `TELESESSION_TEST_TELEPTY_DIR` above:
**190 tests /187 passed /zero failed /three skipped**,33.5s.
Log: `/tmp/telesession-candidate-complete-20261031.log`.
The three skips are native Windows credential persistence (TV20), native Windows
lexical path refusals (TV20), and the intentionally unsupported simulated-win32
credential test over POSIX paths. They are not native acceptance results.

Existing Telepty capability suite passed16/16. Consumer real integration passed9/9
(13 stub tests excluded by name in that scoped run). Independent new uncertainty
tests passed7/7; independent final uncertainty+durability composition passed55/56,
zero failed, one native Windows skip. No Important/Critical source/test finding
remained. Modified JavaScript syntax and git diff checks pass.

The first broad consumer run reported five failures, including nested test
aggregation: absent external RC5 child fixture, forged-audit fixture timestamp
outside its own request window, obsolete500-as-refusal assertion, and an assumed
REST message-ID field in the receiver-full adaptation.
These were corrected without relaxing production auth, identity, durability or
no-replay guards. The next run had only Node's accidental discovery of the child
fixture as a test; moving it outside test/ resolved that. Final run is fully green
apart from the three explicit native/platform skips above.

RC5 now uses a checked-in consumer-owned `test-support` child fixture copied from
the existing local Telepty candidate fixture, without changing its behavior. It
rejects production3848/non-loopback, has a bounded lifetime, retains its synthetic
spawn-time bearer and never prints it. It is not npm-packaged runtime support.
The real private-daemon restart test passed; no operating daemon was restarted.
The forged-audit test now puts its row inside the declared window, so rejection
actually tests identity rather than silently filtering on time.

Logs: `/tmp/telepty-capabilities-compat-20261031.log`,
`/tmp/telesession-real-candidate-20261031.log` (original eight pass/one fail),
`/tmp/telesession-http-unknown-green-20261031.log`,
`/tmp/telesession-audit-unknown-red-20261031.log`,
`/tmp/telesession-candidate-real-final-20261031.log`,
`/tmp/telesession-independent-durable-unknown-final.log`.

## Limits

This validates core API/loopback transport and private fixtures, not the remote
MCP gateway, current Dot or a Mac/provider. The429 was not retried or resolved.
The consumer still uses configured daemon bearer authentication; this does not
implement strict-principal enrollment or enlarge foreign principal trust.
Installed0.9.1 remains untouched and is not made compatible by local source tests.
No Mac injection, production session/config/data change, installation, service
restart, network/security/credential change, remote push or deployment occurred.
