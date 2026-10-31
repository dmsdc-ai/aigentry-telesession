# Install and use the local candidate

This is an installable **stdio MCP** candidate, not a published registry release
or a remote gateway. Local tarball installation and installed-command roundtrip
were tested on Linux, Node20.20.0/npm10.8.2. Native macOS/Windows and the current
remote client/gateway were not tested. `private:true` remains a publication gate.

## Prerequisites

1. Node>=20, npm, and a reviewed tarball. Runtime dependencies are the MCP SDK and
   zod; no source build is needed. The test used a new npm installation tree with
   offline public dependency cache, not a linked source node_modules directory.
2. An already running, separately managed compatible local Telepty. Its authenticated
   `/api/meta` must advertise `inject-exact-target`, `register-create-only` and
   `delete-owned-session`. The observed installed0.9.1 lacks these; do not assume
   compatibility from version alone. No Telepty install/restart is performed here.
3. An operator-selected exact target under the daemon's existing peer policy and
   an operator-provided token file. Installation grants no new authority and does
   not enroll a target, discover credentials or relax peer policy.

## Install the artifact

Choose an application directory and install the reviewed artifact there:

```sh
npm install --ignore-scripts --no-audit --no-fund --prefix /absolute/app-directory /absolute/dmsdc-ai-telesession-0.1.0.tgz
/absolute/app-directory/node_modules/.bin/telesession-mcp --help
/absolute/app-directory/node_modules/.bin/telesession-mcp --version
```

The filename/version describes the current local artifact, not an existing npm
release. A source developer can create it with `npm pack --ignore-scripts`.
Registry access may be needed to resolve dependencies unless an offline cache is
already available; this session's install was explicitly offline. Package files
include both executable entrypoints, runtime modules, README, docs and the linked
API contract. No global PATH, service or shell profile is changed by this recipe.

On platforms where npm's shell shim differs, an MCP client can launch the installed
JavaScript directly with its absolute Node path, as below. This does not imply
that native Windows/macOS acceptance has been completed.

## Configure the MCP client explicitly

Use its supported stdio MCP server configuration; field nesting depends on the
client. This is a server entry, with placeholders rather than credentials:

```json
{
  "command": "<absolute-node-executable>",
  "args": ["/absolute/app-directory/node_modules/@dmsdc-ai/telesession/bin/telesession-mcp.js"],
  "env": {
    "TELESESSION_TARGETS": "<exact-authorized-target>",
    "TELESESSION_INBOX_PREFIX": "<unique-prefix>",
    "TELESESSION_TELEPTY_URL": "http://127.0.0.1:<compatible-daemon-port>",
    "TELESESSION_TELEPTY_TOKEN_FILE": "<absolute-operator-provided-token-file>"
  }
}
```

The token file holds either the bare token or `{"authToken":"..."}`. Protect it
through the host's existing credential controls; do not put a token in arguments,
chat or source control. Use exactly one token source. The URL is explicit loopback;
it does not accept `localhost`, credentials, paths, query strings or remote hosts.
Bare invocation serves stdio only. `--help`/`--version` do not initialize config or
state; all other arguments refuse before startup. The separate tunnel-child helper
accepts no arguments and requires a token file; it does not host a tunnel.

For restart-aware request records, explicitly set `TELESESSION_STATE_DIR` to a
private application state directory such as an absolute `.local/state/telesession`
path. Without it, deduplication/replies are memory-only. State holds hashes and
request metadata, not prompt text or the daemon token. POSIX-only optional inbox
credential persistence is separate; native Windows credential persistence is not
supported. Abrupt-crash locks are not automatically removed or taken over.

## Diagnose before sending

The client should expose exactly five tools. Call `telesession_health`, then
`telesession_list_targets`. These do not register an inbox or send a message.

| Result | Meaning / next step |
|---|---|
| No missing capabilities; exact target present | Prerequisites observed, not delivery or completion. |
| DAEMON_LACKS_CAPABILITY | Compatible Telepty deployment is required separately; this package will not upgrade it. |
| DAEMON_HTTP_401 / DAEMON_UNREACHABLE | Verify the operator's selected local endpoint/token source and service status; do not bypass authentication. |
| TARGET_NOT_ALLOWED / TARGET_NOT_PRESENT | Use an exact authorized present target; no alias or foreign fallback. |
| PEER_INJECT_BLOCKED | Existing daemon policy refused the route; do not wrap/bypass it or auto-add sessions. |
| STORE_LOCKED / STORE_CORRUPT / INBOX_COLLISION | Retain existing evidence and obtain reviewed recovery; do not blindly delete locks or replace another inbox. |
| Remote MCP404/429 | This is outside local stdio hosting. Check the separately managed gateway; respect retry limits. Local install success does not repair it. |

## Send, observe and close safely

Use a stable `request_id` for one logical request. `telesession_send` targets one
exact allowlisted session. Acceptance is separate from delivery; use
`telesession_receipt` for transport observations. The target must answer using its
current credential with first line `REPLY <nonce>` into the returned inbox.
`telesession_read_reply` returns text only after matching audit attribution.
Untrusted/spoofed/stale replies remain quarantined counts.

An inject5xx or explicit uncertainty remains unknown, including after restart.
Do not retry with a new key to erase uncertainty. A verified `failed:*` audit row
proves attribution, not zero effect. Receiver503 preserves unknown payload without
automatic replay when space returns. No exactly-once, application-consumption or
task-completion guarantee is made; completion_fact remains null.

Closing the MCP client ends stdin and invokes owned cleanup. SIGINT/SIGTERM and
supported SIGHUP also request graceful close. Only the created inbox and its current
credential are used for deletion; targets are preserved. Retained/registration-unknown
outcomes need reviewed operator cleanup. SIGKILL/crash cannot promise graceful cleanup.

## Verified scope and release boundary

The installed-artifact acceptance exercises all five tools, durable send, same-ID
deduplication, credential-verified reply, no-secret state and owned shutdown against
private synthetic Telepty. It does not validate a current Mac/provider or remote
gateway. See [compatibility evidence](2026-10-31-candidate-compatibility.md) and
[status](status.md). Maintainers can reproduce installed acceptance with explicit
`TELESESSION_TEST_INSTALLED_PACKAGE` and `TELESESSION_TEST_TELEPTY_DIR`, then
`npm run test:installed`; these are test fixture selectors, not runtime configuration.

Before any remote release, specify the source target, registry package/version/
dist-tag/access, review the exact artifact and obtain posting/deployment authorization.
Source repository is dmsdc-ai/aigentry-telesession; current package is
@dmsdc-ai/telesession@0.1.0 with private:true. No remote push, registry publication,
gateway hosting, credential provisioning or operational Telepty change was performed.
