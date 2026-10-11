# telesession (0.1.0 candidate — work in progress, not released)

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

> **Status: candidate, not released.** `package.json` keeps `"private": true` and nothing is published
> to npm. Real Dot, tunnel, real-daemon and native cross-OS acceptance are **NOTRUN**. See
> [`docs/status.md`](docs/status.md) for exactly what has and has not been verified. This work is
> tracked under task 1215 for the next aigentry release.

## Requirements and prerequisites
telesession refuses to start sending unless the telepty daemon advertises three opt-in capabilities in
`GET /api/meta`: `inject-exact-target`, `register-create-only` and `delete-owned-session`.
**The existing telepty 0.8.5 baseline does not provide them**, so the stock npm telepty package does not
work with this candidate. A telepty build carrying the candidate daemon change is a prerequisite; it is
not part of this repository and has not been released.

There is no one-command install. To try the candidate locally you need:
1. Node ≥ 20.
2. A clone of this repository and `npm install` for its two dependencies
   (`@modelcontextprotocol/sdk`, `zod`).
3. A local telepty daemon built from the candidate change (the three capabilities above), listening on
   loopback, with its auth token available in a file.
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
`telesession_health`, `telesession_list_targets`, `telesession_send {target, text, request_id?, destination?}`,
`telesession_receipt {inject_id}`, `telesession_read_reply {nonce, wait_ms, cursor?}`,
`telesession_request_status {nonce, cursor?}` — strict schemas, JSON results, `completion_fact: null` on
every result. `cursor`, `destination` and `request_status` use the correlation ledger (durable mode only,
`<state dir>/ledger`); see `docs/specs/2026-10-11-e2e-delivery-protocol.md`. `request_status` turns
`completed` once your cursor covers the first final reply (`first_ack_seq`); a later final reply keeps it
`completed` but adds `NEWER_FINAL_ACK_UNREAD` to `status_reasons` until you read it.

Flow: `send` injects `[telesession nonce=<n> reply-to=<inbox> correlation=<id>]` + newline + text into the exact
target (`exact_target:true`, no alias fallback). The target answers from its own telepty session into
`<inbox>` with first line `REPLY <nonce>`; a reply that is the final ACK carries `[telesession ack=final]` on
one of its first three lines (any other verified reply is an addendum). A destination must not echo the
origin prompt (or its header region) in the first three lines of a reply. `send` returns the immutable
`correlation_id` (32 hex) that is also on the wire header. `read_reply` returns the text only after the audit check;
otherwise counts per reason. `receipt` is a transport observation, never a reply. A send without a
response is `accepted: "unknown"` and is never re-sent. `daemon_restart`
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

## Lifetime
The inbox belongs to the process that created it. `close()` (the MCP command calls it on stdin
end/close, SIGINT, SIGTERM and, where the platform delivers it, SIGHUP) closes the listener and makes
at most ONE owned `DELETE` with the inbox's own credential; a refusal is `retained`, never "cleaned".
Crash/SIGKILL or a lost registration response leaves an inbox record for operator cleanup.

## Not provided yet
Automatic unlock after an abrupt crash, native-Windows credential storage, exactly-once delivery,
outbound HTTPS relay, remote auth route/hosting, events/webhooks (unsolicited orchestrator → client).
A local stdio MCP server does not by itself establish a remote ChatGPT/Dot connection.

## More
- [`docs/status.md`](docs/status.md) — verification status and limits of this snapshot
- [`docs/architecture.md`](docs/architecture.md) — boundary, modules, telepty HTTP surface used
- [`API-CONTRACT-TELESESSION.md`](API-CONTRACT-TELESESSION.md) — API contract
