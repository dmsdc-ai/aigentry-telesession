# telesession 0.2.0 (release candidate — not yet published)

telesession is a generic, terminal-independent **remote session connection layer**: an MCP adapter and
a request/reply transport that sit on top of a local telepty daemon.
It sends a prompt to ONE exact, operator-allowlisted telepty session, receives replies on an inbox
session it owns, and returns a reply only when telepty's audit log attributes it to that target's
current credential.

- **One-way dependency.** telesession → telepty's documented HTTP API. telepty does not depend on
  telesession and runs without it.
- **No client-specific branching.** A Dot, a CLI or any other MCP client is just an operator-configured
  consumer; there is no product-specific code path.
- **Plain Node ≥ 20** (no shell, no OS GUI API), intended for macOS, Linux and Windows.

> **Status: 0.2.0 release candidate, not yet published.** The package is prepared for public npm
> publication as `@dmsdc-ai/telesession` (`publishConfig.access: "public"`). Publication is a separate,
> gated step. The integrated 0.2.0 source has **not yet been tested** as a whole. Earlier Linux
> private-daemon and local-tarball runs covered pre-integration lines only. Real Dot, remote gateway/tunnel
> and native macOS/Windows acceptance are **NOTRUN**. See [installation](docs/install.md).

## Requirements and prerequisites
telesession refuses to start sending unless the telepty daemon advertises three opt-in capabilities in
`GET /api/meta`: `inject-exact-target`, `register-create-only` and `delete-owned-session`.
**Telepty 0.10.0 is the prerequisite for supported 0.2.0 behaviour.** It is not yet published. The
earlier Telepty 0.9.1 and 0.8.5 do not provide these capabilities. Version numbers alone do not establish
compatibility: the daemon must advertise all three capabilities. Its inject delivery-uncertainty answer
must also match: a non-2xx with `delivery_uncertain: true` or code `DELIVERY_UNCERTAIN`, and an audit
`failed:DELIVERY_UNCERTAIN` row. No installed or runtime proof of this candidate with Telepty 0.10.0
exists yet. This package never upgrades or restarts Telepty automatically.

Once published, `npm install @dmsdc-ai/telesession@0.2.0` installs it without a source build.
[Installation and MCP configuration](docs/install.md) describes the flow. You need:
1. Node ≥ 20.
2. The package installed with its two dependencies (`@modelcontextprotocol/sdk` ^1.29.0, `zod`
   ^3.25.76), or a source checkout installed from its lockfile.
3. A local Telepty 0.10.0 daemon (the three capabilities above), listening on loopback, with its auth
   token available in a file.
4. An exact target session that the daemon's existing `AIGENTRY_ORCHESTRATOR_SIDS` policy treats as a
   true orchestrator (configured by the operator, outside telesession).

## Configuration (operator only; checked before any telepty request)
| env | rule | refusal code |
|---|---|---|
| `TELESESSION_TARGETS` | 1–8 unique exact session ids (space/comma separated), `^[A-Za-z0-9._-]{1,128}$` | `CONFIG_TARGETS_INVALID` |
| `TELESESSION_INBOX_PREFIX` | `^[A-Za-z0-9._]{1,48}$` | `CONFIG_INBOX_PREFIX_INVALID` |
| `TELESESSION_TELEPTY_URL` | exactly `http://127.x.y.z:<port>` or `http://[::1]:<port>`; no credentials, path, query, `localhost` (refused, never stripped) | `CONFIG_URL_INVALID` |
| `TELESESSION_TELEPTY_TOKEN` **or** `TELESESSION_TELEPTY_TOKEN_FILE` | exactly one. The file must be an absolute path to a regular file ≤ 64 KiB holding either the bare token or a telepty `config.json` (`{"authToken": "..."}`) | `CONFIG_TOKEN_SOURCE_CONFLICT`, `CONFIG_TOKEN_MISSING`, `CONFIG_TOKEN_FILE_INVALID`, `CONFIG_TOKEN_INVALID` |
| `TELESESSION_STATE_DIR` (optional) | absolute, normalized, 1–512 chars, no control chars, no trailing separator (win32: no UNC/device/drive-relative). Private app state, e.g. `~/.local/state/telesession`; never home/cwd itself, a project dir or telepty's own state | `CONFIG_STATE_DIR_INVALID`; at open `STORE_PATH_FORBIDDEN`, `STORE_PERMISSIONS_INVALID`, `STORE_LOCKED`, `STORE_CORRUPT`, … |
| `TELESESSION_PERSIST_INBOX_CREDENTIAL` (optional) | unset/`0` or `1`; `1` requires a state dir and verified POSIX permissions (refused on Windows) | `CONFIG_PERSIST_INVALID`, `CONFIG_STATE_DIR_REQUIRED`, `STORE_CREDENTIAL_PLATFORM_UNSUPPORTED` |
| `TELESESSION_RELAY_INTERVAL_MS` (optional, **unsupported in 0.2.0** — see [Relay](#relay-and-destination-unsupported-in-020)) | unset/`0` = relay runner off (default); otherwise an integer 1000–3600000 ms, requires a state dir. Turning it on in a live deployment is a separate approval (spec §10). One tick on demand: `telesession-relay-tick` (refuses a held ledger lock, exit 3) | `CONFIG_RELAY_INTERVAL_INVALID`, `CONFIG_STATE_DIR_REQUIRED` |

| `TELESESSION_RESPONDER` (optional, **default off** — see [Scoped responder](#scoped-responder-issue-18-opt-in-default-off)) | unset/anything but `1` = off. `1` activates `telesession-responder-pump` only; it changes who can cause a trusted send and is a separate approval | `RESPONDER_NOT_ACTIVATED` |
| `TELESESSION_RESPONDER_TOOL_ENV` (required with the responder) | must be `filtered`: the operator's declaration that the model's tool runtime does NOT inherit the session credential. Verify it by running `env \| grep TELEPTY_SESSION` **inside that tool shell** and seeing no output | `RESPONDER_TOOL_ENV_UNVERIFIED` |
| `TELESESSION_RESPONDER_DROP_DIR` (optional) | absolute, normalized path of the private drop directory the tool runtime writes to; owner-only (POSIX only — the responder refuses Windows). It may not contain, or live inside, the state dir | `RESPONDER_DROP_DIR_INVALID`, `RESPONDER_DROP_DIR_OVERLAPS_STATE`, `RESPONDER_DROP_PERMISSIONS_INVALID` |

No defaults, no `~/.telepty` lookup, no credential minting. The token never appears in tool
arguments, results, logs or the state dir. telepty's own peer-lane guard still applies and is not
bypassed: full prompt exchange is only for a target the operator has designated as a true
orchestrator in the daemon's existing `AIGENTRY_ORCHESTRATOR_SIDS` policy. Never add inbox ids or
arbitrary sessions to that list, and never wrap work requests in ask-request/ask-reply envelopes to get
past the guard. Otherwise sends fail with `PEER_INJECT_BLOCKED`, which is reported as-is.

Example MCP client entry (placeholders only; never put a token value here):
```json
{ "command": "<absolute node executable>",
  "args": ["<absolute path to telesession>/bin/telesession-mcp.js"],
  "env": { "TELESESSION_TARGETS": "<exact target sid>", "TELESESSION_INBOX_PREFIX": "<prefix>",
           "TELESESSION_TELEPTY_URL": "http://127.0.0.1:<port>",
           "TELESESSION_TELEPTY_TOKEN_FILE": "<absolute path to 0600 token or telepty config.json>" } }
```

## MCP tools
Six tools: `telesession_health`, `telesession_list_targets`, `telesession_send {target, text, request_id?, destination?}`,
`telesession_receipt {inject_id}`, `telesession_read_reply {nonce, wait_ms, cursor?}`,
`telesession_request_status {nonce | request_id | correlation_id, cursor?}` — strict schemas, JSON results, `completion_fact: null` on
every result. `cursor`, `destination` and `request_status` use the correlation ledger (durable mode only,
`<state dir>/ledger`); see `docs/specs/2026-10-11-e2e-delivery-protocol.md`. `destination` is unsupported in
0.2.0 (see [Relay](#relay-and-destination-unsupported-in-020)). `request_status` turns
`completed` once your cursor covers the first final reply (`first_ack_seq`); a later final reply keeps it
`completed` but adds `NEWER_FINAL_ACK_UNREAD` to `status_reasons` until you read it.
After the 15-min nonce TTL, `read_reply` still answers `NONCE_EXPIRED` when nothing is stored. When the ledger
holds verified replies for that nonce, it returns them with `source: "ledger"` and `expiry: "NONCE_EXPIRED"`
(text/received_at/verified_sender.sid from ledger seq 1; no audit `inject_id`). For callers written before
this ledger read path: the post-expiry answer is a success (`ok: true`), not the `NONCE_EXPIRED` error, so branch on
`source`/`expiry` rather than on the error; it carries no `inject_id`, and `wait_ms` is ignored (it answers at
once from the ledger, without waiting). `request_status` (exactly one
lookup key) keeps answering with `transport_nonce: "expired"` and `TRANSPORT_NONCE_EXPIRED`, and still records
your cursor as the final receipt.

Flow: `send` injects `[telesession nonce=<n> reply-to=<inbox> correlation=<id>]` + newline + text into the exact
target (`exact_target:true`, no alias fallback). The target answers from its own telepty session into
`<inbox>` with first line `REPLY <nonce>`; a reply that is the final ACK carries `[telesession ack=final]` on
one of its first three lines (any other verified reply is an addendum). A destination must not echo the
origin prompt (or its header region) in the first three lines of a reply. `send` returns the immutable
`correlation_id` (32 hex) that is also on the wire header. `read_reply` returns the text only after the audit check;
otherwise counts per reason. `receipt` is a transport observation, never a reply. A send without a
response is `accepted: "unknown"` and is never re-sent. The same holds for an inject answered with HTTP 5xx,
`delivery_uncertain: true` or code `DELIVERY_UNCERTAIN`: such a response is not proof of zero effect.
Durable audit recovery treats a `failed:*` audit row as `recovery: "unverified"` (still uncertain), never
as refused. A receipt with tracking state `aborted` alone is `unknown`, not `refused`. `daemon_restart`
(`observed`/`not_observed`/`unknown`) is a pid comparison, reported only.

### Reply trust
A reply is `trusted` only with exactly one audit row whose payload sha256 matches, whose verified
sender sid and epoch equal the target's, with no spoof suspicion, inside the nonce window and with an
unbound inject id. Anything else is counted by reason and not returned as a reply.

### Dedupe
`request_id` (`^[A-Za-z0-9._:-]{1,128}$`, optional): the same id with the same target and the exact
same text returns the earlier record (`deduplicated: true`, zero telepty requests). A different target
or text gives `REQUEST_ID_CONFLICT`, and a send still running gives `REQUEST_IN_FLIGHT`. An `uncertain`
send is never re-sent. With a state dir this holds across restarts until 24 h after the nonce expires;
without one it holds within the process only. Never exactly-once.

## Durable store (opt-in `TELESESSION_STATE_DIR`)
One writer per state dir, held by an exclusive lock file; `state.json`, `replies/` and the optional
inbox credential are fsynced. A graceful close releases the lock. **After an abrupt crash the lock
stays and every restart is refused with `STORE_LOCKED`**; automatic unlock is not provided. On a normal
restart the inbox keeps its id (owned DELETE with a persisted credential, then `create_only`) or is
rotated to a new id; the old id is listed in `health.store.orphans` and never touched again. Replies
sent while the receiver or inbox is down can be lost: `reply_loss_possible` and
`unreceived_audit_rows` (a lower bound; 0 is not proof of no loss) report it, and nothing is replayed.
The state dir never holds the telepty token, the receiver secret or prompt text (hashes only).
Without a state dir everything is memory only.

## Assistant profiles (issue #16; needs Telepty `client-profile-scope-v1`, Telepty ≥ 0.11.0)
Several assistants on one host can each use their own inbox prefix, targets, durable state dir and lock, and
**their own Telepty client credential**. The daemon enforces that credential (create, read, inject and delete
only inside the profile's own namespace and granted targets). Profile mode is opt-in. Without it, nothing
changes (shared-control mode).

| env | rule | refusal code |
|---|---|---|
| `TELESESSION_PROFILE` + `TELESESSION_PROFILES_FILE` | both or neither; name `^[a-z0-9][a-z0-9._-]{0,63}$`; the file path is absolute | `CONFIG_PROFILE_MISSING`, `CONFIG_PROFILES_FILE_MISSING`, `CONFIG_PROFILE_INVALID`, `CONFIG_PROFILE_UNKNOWN` |
| legacy keys | in profile mode `TELESESSION_TELEPTY_TOKEN`, `_TOKEN_FILE`, `_TARGETS`, `_INBOX_PREFIX`, `_STATE_DIR`, `_PERSIST_INBOX_CREDENTIAL` and `_TELEPTY_URL` must be unset (`TELESESSION_RELAY_INTERVAL_MS` stays allowed) | `CONFIG_PROFILE_CONFLICT` |
| platform | native Windows is not supported in profile mode | `CONFIG_PROFILE_PLATFORM_UNSUPPORTED` |
| `AIGENTRY_ORCHESTRATOR_SIDS` (optional) | when non-empty, the profile's targets are intersected with it (never widened) | `CONFIG_TARGETS_INVALID` |

Profiles file (operator-private, synthetic example):
```json
{"schema":"telesession.profiles/v1","telepty_url":"http://127.0.0.1:3848",
 "profiles":{"example-a":{"inbox_prefix":"exa","targets":["example-target-1"],
   "state_dir":"/abs/state/example-a","token_file":"/abs/secrets/example-a.token","persist_inbox_credential":false}}}
```
- The profiles file and each token file must be a regular file that is not a symlink, has exactly one link,
  is owned by you, has mode `0600` (no group/other bits) and is ≤ 64 KiB. Otherwise:
  `CONFIG_PROFILES_FILE_INVALID` / `CONFIG_TOKEN_FILE_INVALID`. A malformed file gives
  `CONFIG_PROFILES_INVALID`. `telepty_url` follows the `TELESESSION_TELEPTY_URL` rule (`CONFIG_URL_INVALID`).
  Each profile has 1–8 targets.
- A token file holds exactly one bare `tpc1.<generation>.<43 base64url>` client token, as minted by
  `telepty client-profile mint`. The shared telepty `{"authToken":…}` form and any other text give
  `CONFIG_PROFILE_TOKEN_INVALID`, so a profile can never be pointed at the shared root token.
- Checked over the whole file: inbox prefixes are unique case-insensitively (`CONFIG_PROFILE_CONFLICT`).
  State dirs are pairwise distinct and not nested, compared by path, realpath and dev:ino, and
  case-insensitively on macOS (`CONFIG_PROFILE_STATE_ALIAS`). Token files are not aliased to each other
  and not inside any state dir (`CONFIG_PROFILE_CREDENTIAL_ALIAS`). Only the selected token file is read.
- On the wire, profile mode sends only `x-telepty-client-token`, never `x-telepty-token`, and never falls
  back. Before any own operation, `/api/meta` must list `client-profile-scope-v1`. It must also return a
  server-computed `caller` with `kind:"client-profile"`, this profile, this prefix, every configured target,
  `enforcement:"server"`, `shared_token:false` and the token's generation.
  - A daemon without the feature, or a rejected or rotated token (401/403), gives `PROFILE_CREDENTIAL_REJECTED`.
  - 503 gives `PROFILE_REGISTRY_UNAVAILABLE`.
  - A 200 without the capability gives `DAEMON_LACKS_CAPABILITY`.
  - Any other caller mismatch gives `PROFILE_NOT_ENFORCED`.
  - In every one of these cases nothing is registered, injected, read or deleted.
- `telesession_health` adds
  `credential {mode: "client-profile"|"shared-control", profile, server_enforced, shared_token_in_use, generation}`,
  taken from the server's answer. `server_enforced:null` plus `code` means the server could not be asked.
  Paths, tokens and digests are never reported.

Threat model. Profile scope separates assistants that hold **different credentials**. Within one OS user,
any process can read every token file, the profiles file and process environments, and can choose another
`TELESESSION_PROFILE`. Profile selection is configuration, not authentication. Use separate OS accounts for
that boundary. Daemon capacity (audit query workers, tracking ledger) is shared: 429/503 from one
profile's load are reported as-is (retryable), not as an enforcement failure. Profile mode is unsupported
on native Windows. Without a Telepty that implements `client-profile-scope-v1`, profile mode refuses to
operate. It is not complete until a real Telepty build passes `test/real-daemon-profile.test.js`.

## JS API (no MCP needed)
```js
import { loadConfig, createTeleptyTransport } from "@dmsdc-ai/telesession";
const t = createTeleptyTransport(loadConfig(process.env));
const s = await t.send({ target: "<exact target sid>", text: "hello" });
const r = await t.readReply({ nonce: s.nonce, wait_ms: 30000 });
await t.close(); // → { inbox_id, outcome: deleted|retained|not_created|collided|registration_unknown }
```
The MCP adapter is `import { registerMcpTools } from "@dmsdc-ai/telesession/mcp"`.

## Clean-environment launcher (candidate)
`bin/telesession-tunnel-child.js` starts `bin/telesession-mcp.js` with an exact env allowlist
(`TELESESSION_*` config keys plus a few platform essentials), refuses any CLI argument and refuses a
token *value* (`TELESESSION_TELEPTY_TOKEN_FILE` is required). It is **not an OS sandbox**: the child runs
as the same user. See [`docs/tunnel-child.md`](docs/tunnel-child.md). Independent verification and
security triage of the launcher were still ongoing at this snapshot.

## Relay and `destination` (unsupported in 0.2.0)
The relay runner, the `telesession-relay-tick` CLI and `telesession_send.destination` ship in 0.2.0
but are **unsupported and default-off**, and no request can complete through them:
- `destination` is experimental metadata and is not routed end to end. An origin `telesession_send`
  with a `destination` still injects the allowlisted `target` on the local daemon (a real effect). Only
  the correlation record names the destination, and it can remain `pending`.
- `PEER_UNSUPPORTED` applies to relay items for another peer, which are refused before any inject. It
  does not refuse an origin send. A daemon-side exact remote forward does not exist yet (telepty#111).
- The outbox is not wired: `ledger.enqueue()` has no caller in the shipped processes, so the runner
  has nothing to send.
- Relayed receipts cannot be bound to the origin inject and are refused (`INJECT_MISMATCH`, #8).
  Remote sender provenance is unavailable (`REMOTE_PROVENANCE_UNAVAILABLE`, telepty#100).
- A request with a `destination` stays `pending`/unproven. **`pending` is never completed remote
  delivery.** Do not treat it as one.

Enabling `TELESESSION_RELAY_INTERVAL_MS` in a live deployment is a separate approval.

## Scoped responder (issue #18; opt-in, default off)
Some clients filter the environment of the model's tool runtime, so a reply the model sends from there
has no session id, token or credential path and arrives as a `claimed_only` candidate whose body stays
quarantined. The scoped responder lets such a session answer **without** giving its tool runtime a
reusable session bearer:

1. The host records the trusted inbound request binding. A request text alone proves nothing: the
   responder accepts it only when this daemon's audit holds exactly one row (complete page) carrying
   that payload to this session — stamped `trusted-local`, delivered, not spoofed, and **verified** as
   sent by that request's own reply-to inbox — and only when the daemon's observation of that same
   inject names this session and its current instance. A second delivery of the same payload, verified
   or not, makes it ambiguous and issues nothing. The deadline comes from that row, not from the claim.
2. The tool runtime gets only `{binding_id, challenge}` — single use, bound to that one request,
   expiring with the requester's own deadline, no bearer.
3. The tool runtime writes `<drop>/replies/<binding_id>.json` with `{v, binding_id, challenge, body}`.
   `body` is the only caller-supplied content; a file naming a destination, nonce or principal is
   refused, not obeyed. Before its one inject the host re-proves its own instance, checks the
   requester's instance and reconciles the daemon's audit against its own send history; then it composes
   `REPLY <nonce> <body>` and injects it with the session credential it already owns.

```
TELESESSION_RESPONDER=1 TELESESSION_RESPONDER_TOOL_ENV=filtered \
  TELESESSION_RESPONDER_DROP_DIR=<abs private dir> \
  TELEPTY_SESSION_ID=<this session id> TELEPTY_SESSION_TOKEN=<this session's token> \
  telesession-responder-pump     # one bounded pass; exit 0 ran, 1 failed, 2 config/activation, 3 state
```

Run it in the **session host** process, where those variables exist — never in the model's tool shell,
which is exactly the environment that has none of them. Bindings, outcomes and a bounded audit of every
acceptance and refusal live in `<state dir>/responder` under their own lock; the bearer, the challenge,
the request text and the reply body are never persisted (digests and hashes only).

**What holds, and where.** Each committed record is authenticated with a key derived from the session
credential this host process holds in memory and never writes down, so a process that cannot read that
credential cannot edit, transplant or forge a binding — an altered file is refused
(`RESPONDER_STATE_UNAUTHENTIC`), one from another credential instance is refused
(`RESPONDER_CREDENTIAL_ROTATED`). Because a one-shot command cannot by itself tell an authentic older
snapshot from the current one, the daemon's audit — which the tool runtime cannot write — decides
whether this instance has already replied: an audit row that this store's own history does not account
for refuses the send (`AUDIT_UNACCOUNTED_REPLY`). **This guarantee covers the configuration issue #18 is
about, where the tool runtime does not hold the session credential.** A tool runtime that does hold it
(for example codex-cli with its default shell policy) can reply as the session directly, with or without
this component, so nothing here constrains it; that is why `TELESESSION_RESPONDER_TOOL_ENV=filtered` is
required, and the operator must verify it. A same-user actor can always delete or corrupt the drop
directory or the state file and stop replies from working (denial of service); it cannot redirect or
duplicate a trusted send.

At most one authenticated send per binding: a duplicate returns the recorded outcome, an expired
binding is refused and an earlier result is preserved, a rotated session credential cannot even open the
state, and a send interrupted by a restart stays `uncertain` and is never repeated (still not
exactly-once). Quarantine is unchanged: nothing that is quarantined today becomes readable, and a
request without verified sender evidence gives the tool runtime no reply route at all.

**Activation step (separate approval).** Set `TELESESSION_RESPONDER=1` (with
`TELESESSION_RESPONDER_TOOL_ENV=filtered`) for that one host process after approval. Without it the
command refuses (`RESPONDER_NOT_ACTIVATED`) and no other code path in this package reaches the
responder. **Windows is refused** (`RESPONDER_PLATFORM_UNSUPPORTED`): this implementation does not
verify Windows ACLs, so it does not claim that protection. Profile mode (issue #16) is not supported
yet either (`RESPONDER_PROFILE_UNSUPPORTED`). After an abrupt exit the directory stays locked
(`RESPONDER_LOCK_STALE` when the holder is gone, `RESPONDER_LOCKED` while it lives); recovery is the
operator removing `<state dir>/responder/lock` once no pump is running, exactly as for the other stores.

## Known limitations
- **Silent reply rejection (#10, open).** The durable inbox rejects a verified-format reply with 503 when
  a request already holds 4 reply candidates or the store holds 64 reply texts. Only the generic
  `inbox_rejected` counter changes: there is no per-reason counter, and the request is not marked.
  With Telepty 0.10.0 a receiver 503 is dead-lettered as `unknown` and not retried, so that reply is
  lost unless the replier sends it again. The minimum follow-up is separate reason counters (for example
  `candidates_full` and `store_full`) and marking the affected request.
- Uncertain sends (`accepted: "unknown"`) release their ledger reservation and have no ledger record
  until durable audit recovery reconstructs them.

## Lifetime
The inbox belongs to the process that created it. `close()` (the MCP command calls it on stdin
end/close, SIGINT, SIGTERM and, where the platform delivers it, SIGHUP) closes the listener and makes
at most ONE owned `DELETE` with the inbox's own credential; a refusal is `retained`, never "cleaned".
Crash/SIGKILL or a lost registration response leaves an inbox record for operator cleanup.

## Not provided yet
Automatic unlock after an abrupt crash, native-Windows credential storage, exactly-once delivery,
remote/multi-hop relay delivery, outbound HTTPS relay, remote auth route/hosting, events/webhooks (unsolicited orchestrator → client).
A local stdio MCP server does not by itself establish a remote ChatGPT/Dot connection.

## More
- [`docs/install.md`](docs/install.md) — installation and MCP client configuration
- [`docs/specs/2026-10-11-e2e-delivery-protocol.md`](docs/specs/2026-10-11-e2e-delivery-protocol.md) — correlation/ledger protocol
- [`CHANGELOG.md`](CHANGELOG.md) — changes per version
- [`docs/architecture.md`](docs/architecture.md) — boundary, modules, telepty HTTP surface used
- [`API-CONTRACT-TELESESSION.md`](API-CONTRACT-TELESESSION.md) — API contract
