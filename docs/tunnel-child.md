# telesession-tunnel-child — clean-environment MCP child launcher

`bin/telesession-tunnel-child.js` (logic in `src/tunnel-child.js`) is a cross-platform first-party entry
point for a tunnel client that launches telesession over stdio. It exists because the reviewed
tunnel-client 0.0.16 (`5f99daab…`) starts stdio children with **its whole process environment**, has
no per-command `env:` in YAML, and logs the command argv verbatim at child start and exit.
`env -i` covers this on POSIX but has no Windows equivalent.

## What it does

1. Refuses any CLI argument (`TUNNEL_CHILD_ARGS_UNEXPECTED`). There is no command, arg, path or shell override.
2. Builds a new child environment from an exact allowlist; everything else is dropped.
3. Runs `<process.execPath> <package>/bin/telesession-mcp.js`, with the entry resolved from the
   module's `import.meta.url`: `shell:false`, `stdio:"inherit"`, `detached:false`.
4. Exits with the child's exit code (signal-terminated child: `128 + signal number`; spawn failure: `1`;
   refusal before spawn: `2`).

What it is **not**: it is not an OS sandbox. It filters the **child** environment only and does not
sanitize its own already-started process. The child runs as the same OS user and can read any file
that user can read. The outer tunnel launch must itself start from an approved clean environment and
give the control-plane key only as a `file:` reference (`control_plane.api_key: "file:<path>"`).

## Child environment

| Forwarded when present | Notes |
|---|---|
| `TELESESSION_TELEPTY_URL`, `TELESESSION_TARGETS`, `TELESESSION_INBOX_PREFIX`, `TELESESSION_STATE_DIR`, `TELESESSION_PERSIST_INBOX_CREDENTIAL` | Values are forwarded unchanged. `src/config.js` in the child remains the final validator. |
| `TELESESSION_TELEPTY_TOKEN_FILE` | **Required**: nonempty and absolute by the target platform's `path.isAbsolute` (same check as `src/config.js`). Spaces and non-ASCII (e.g. Korean) are fine, because the path travels as an env value and never through argv. |
| win32 only: `SystemRoot`, `WINDIR`, `TEMP`, `TMP` | Platform essentials. |
| POSIX only: `TMPDIR`, `LANG`, `LC_ALL` | Optional. |

- A nonempty `TELESESSION_TELEPTY_TOKEN` is **refused** (`TUNNEL_CHILD_TOKEN_VALUE_FORBIDDEN`), never transferred. An empty one is dropped.
- Never forwarded, among others:
  - `PATH` and `HOME`/`USERPROFILE`
  - `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`
  - `LD_PRELOAD`, `DYLD_*`
  - `*_API_KEY`, `OPENAI_*`, `CONTROL_PLANE_*`, `TUNNEL_CLIENT_*`
  - proxy variables (`HTTP(S)_PROXY`, `NO_PROXY`, any case)
  - any other `TELESESSION_*` key
- Why no `PATH`/`HOME`:
  - The child is an absolute Node binary plus an absolute script.
  - telesession reads only `TELESESSION_*` (`src/config.js`).
  - `os.homedir()` is used only when a state dir is set (`src/store.js`). Node falls back to the OS account database when `HOME`/`USERPROFILE` is unset (libuv `uv_os_homedir`). That fallback is Node behaviour and has not been exercised here.
- Windows key casing:
  - Matching is case-insensitive on win32, and output names are canonical (e.g. `systemroot` → `SystemRoot`, `telesession_targets` → `TELESESSION_TARGETS`).
  - Two case variants of one allowed key are refused (`TUNNEL_CHILD_ENV_AMBIGUOUS`). This includes the token key.
  - On POSIX, names are exact. A lowercase variant is simply an unlisted key and is dropped.
- Values must be strings without NUL (`TUNNEL_CHILD_ENV_INVALID`).
- The child env object has a null prototype, and the parent env is never mutated.

## Exact command shape (placeholders only — never put a secret value here)

Profile (`run --profile-file <profile>`). The command string is logged, so it must contain only
absolute paths:

```yaml
control_plane:
  api_key: "file:<operator 0600 control-plane key file>"
mcp:
  commands:
    - channel: <channel>
      command: "<absolute node executable> <absolute telesession package>/bin/telesession-tunnel-child.js"
```

The outer tunnel-client launch env is approved and clean. It must not export `CONTROL_PLANE_API_KEY`, `OPENAI_API_KEY` or `OPENAI_ADMIN_KEY`. It carries only the non-secret references:

```text
TELESESSION_TELEPTY_URL=http://127.0.0.1:<port>
TELESESSION_TARGETS=<exact target sid>
TELESESSION_INBOX_PREFIX=<prefix>
TELESESSION_TELEPTY_TOKEN_FILE=<absolute 0600 telepty token/config file>
```

- Do not set `TELESESSION_TELEPTY_TOKEN`; the launcher refuses it.
- Live use is memory-only, so leave `TELESESSION_STATE_DIR`/`TELESESSION_PERSIST_INBOX_CREDENTIAL` unset unless the durable mode is separately approved.
- On POSIX, the same references may instead be supplied through the reviewed `env -i` wrapper in the command string. They are non-secret, but they are logged.
- tunnel-client splits the command string without a shell. Whether it honours quoting has not been verified, so prefer install paths without spaces for the **command** (the token-file path is unaffected).

## Lifecycle

- **stdout** is never written by the launcher. The MCP byte stream belongs to the child through inherited stdio. Diagnostics go to stderr as one line with a stable code: `telesession-tunnel-child refused: <CODE>` (exit 2) or `telesession-tunnel-child: TUNNEL_CHILD_SPAWN_FAILED` (exit 1). There are no env values, paths or stacks.
- **Primary shutdown path (all platforms):** the child shares the launcher's stdin handle. When the tunnel client closes stdin, telesession-mcp sees EOF, closes its inbox and exits 0. The launcher then exits with the same code.
- **POSIX signals:**
  - On SIGINT/SIGTERM/SIGHUP, the first signal is forwarded once to the owned child (`child.kill(sig)`).
  - If the child is still alive after 5 s, it gets SIGKILL.
  - The child's own handlers make SIGINT/SIGTERM/SIGHUP graceful.
- **Windows (documented limits):**
  - There are no POSIX signals. `child.kill()` is `TerminateProcess` (forceful, no inbox cleanup).
  - The launcher therefore forwards nothing immediately on SIGINT/SIGBREAK/SIGHUP. The child is attached to the same console and stdin, so it normally stops on its own. Only if it is still alive after 5 s is it terminated.
  - No Job Object is used. If the launcher itself is killed forcefully, the child is **not** killed with it; it ends when its inherited stdin reaches EOF.
- Only the owned child is ever signalled: no process groups, no `detached`, no other pid.
- If the launcher is SIGKILLed, the same stdin-EOF path still ends the child, because the stdin pipe is owned by the tunnel client, not by the launcher.

## Independent verification required before activation (NOTRUN here)

1. Unit run: `node --test test/tunnel-child.test.js`. It uses only fakes (no child, server or network).
2. Real POSIX launch with a scratch env containing decoy keys (`OPENAI_API_KEY=decoy`, `NODE_OPTIONS=…`, proxies). Inspect the child env by name only (e.g. `/proc/<pid>/environ` key names on Linux, or `ps eww` on macOS). Expect exactly the allowlist.
3. Native Windows: casing canonicalization, ambiguous-variant refusal, Node start without `PATH`/`USERPROFILE`, console Ctrl-C/close behaviour, and the grace-period terminate.
4. MCP stdio byte-stream integrity through the launcher (initialize → tools/list) against a test-private telepty.
5. tunnel-client 0.0.16 preflight and a `run` with the profile above. Check that the logged argv shows paths only, and that a child exit stops the daemon as reviewed.
6. Snyk Code scan of `src/tunnel-child.js`, `bin/telesession-tunnel-child.js` and `test/tunnel-child.test.js`.
