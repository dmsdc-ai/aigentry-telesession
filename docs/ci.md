# CI and release verification

Two workflows live in `.github/workflows/`. Both run on GitHub-hosted runners with a read-only token
(`permissions: contents: read`), use no secrets, check out with `persist-credentials: false`, and never
publish, release or deploy anything.

## `ci.yml` — cross-platform unit CI

Triggers: pushes to `main`, pull requests, `workflow_dispatch`, and `workflow_call` (reused by the release check).

| Job | Runners | What it runs |
|---|---|---|
| `unit` | `ubuntu-latest`, `macos-latest`, `windows-latest` × Node `20.20.0` (`fail-fast: false`, 15 min timeout) | `npm ci --ignore-scripts --no-audit --no-fund`, then `npm run --silent test:unit` |
| `pack` | `ubuntu-latest`, Node `20.20.0` (10 min timeout) | `npm run --silent check:pack` (`npm pack --dry-run --ignore-scripts`) |

Pull-request runs for the same ref cancel older ones; `main` pushes run to completion.

Actions are pinned by commit SHA:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` (TAP output, 14 days)

### Exact unit command

```
node --test --test-reporter=tap test/config.test.js test/store.test.js test/tunnel-child.test.js test/tunnel-child-independent.test.js
```

The files are listed explicitly. CI does **not** use `npm test` (`node --test test/`), because auto-discovery
also picks up suites that need a telepty source checkout or the MCP SDK end to end.

### Skips are not passes

The selected files contain skip guards:

- `test/store.test.js`: 12 test sites guarded by `POSIX_ONLY`, some of them in loops. They **skip on Windows**,
  so Windows store coverage is narrower than on Linux/macOS.
- `test/store.test.js`: "native Windows: credential persistence refused…" runs **only on Windows** and skips elsewhere.
- `test/store.test.js`: "simulated win32 (seam)…" **always skips** (marked NOTRUN by design).
- `test/config.test.js`, `test/tunnel-child.test.js` and `test/tunnel-child-independent.test.js` have no skip guards.

Node's TAP `# pass` count excludes skipped tests. The "Test counts" step writes the tests, pass, fail,
cancelled, skipped and todo counts to the job summary, and lists every skipped test by name. It fails the job
if there is no TAP output or zero passing tests. A cancelled test (for example, one that never settles) makes
`node --test` exit non-zero and fails the job.

### Observed hosted run and Windows fixture contracts

Run 38112321584 at main `351966216308962b16ca8986e2b0f17b591fac47`:

- `npm ci` passed on all three OSes. Unit tests passed on ubuntu and macos, and the pack dry-run passed.
- **Windows unit failed:** 101 tests, 63 pass, 10 fail, 28 skipped, 0 cancelled. All 10 failures were in
  `test/store.test.js`, and they come from two test-fixture causes, not a demonstrated store defect:
  1. **Fault-seam path identity (9 vectors).** These are the open/write/fsync tmp faults for ENOSPC and EIO,
     directory-fsync errno handling, graceful-close lock unlink, and ENOSPC on a reply write.
     - `src/store.js` canonicalizes its dir with `fs.realpathSync.native`, and every call it makes uses that form.
     - The sandbox used the JS `fs.realpathSync`, so exact-path predicates (`tmpIn`, `ctx.paths[0] === stateDir`,
       `callsTouching(lock)`) never matched on Windows. The failure was `hits` 0 !== 1.
     - Only the rename vectors passed, because they match on `basename`. The run log does not show the two path
       strings, so the exact difference (8.3 short name or case) is unconfirmed.
     - Fix: the sandbox now uses the same native realpath, and a regression test asserts it on every OS.
  2. **Graceful stop (1 vector).** On Windows `child.kill("SIGTERM")` is TerminateProcess, so the child's SIGTERM
     handler never ran and no `closed` event arrived.
     - Fix: on win32 the fixture sends a cooperative IPC `{cmd:"stop"}`, and the child runs the same
       close → `closed` → exit path. POSIX still uses SIGTERM.
     - The abrupt-crash evidence (SIGKILL, lock stays, `STORE_LOCKED`) is unchanged on every OS.

These fixes are test-side only. They count as verified only once a hosted re-run is green. Fixing them adds
one test, so Windows should report 102 tests.

### What a green matrix proves, and what it does not

It proves that, on each hosted OS with Node 20.20.0:

- the lockfile installs cleanly without lifecycle scripts;
- config normalization/loading, the durable store (real filesystem plus child-process crash cases) and the
  tunnel-child launcher (pure plan construction plus lifecycle driven by an injected fake spawn) pass, minus the
  skips listed above;
- the package tarball contents resolve (`npm pack --dry-run`, Linux only).

It does **not** prove any of the following:

- a real telepty daemon, the Dot/꼬마 connection, native PTY behaviour, or restart/recovery against a live daemon;
- a real launch of `bin/telesession-tunnel-child.js` or `bin/telesession-mcp.js`;
- MCP stdio transport;
- the synthetic-HTTP transport suites (`test/transport-*.test.js`, `test/mcp.test.js`), which are not in this CI;
- Node versions other than 20.20.0. `engines` declares `>=20`, but only 20.20.0 is exercised.

### Node floor

`package.json` declares `"engines": { "node": ">=20" }`. CI pins Node `20.20.0`, the verified baseline. Later
Node lines are not claimed until they are added to the matrix and pass.

## `release-check.yml` — release verification gate

Triggers: `workflow_dispatch` and pushes of tags matching `v*`.

1. `ci` calls `ci.yml` (the full matrix plus pack).
2. `release-gate` runs only after `ci` succeeds (`needs: [ci]`). On tag pushes it checks that the tag equals
   `v` + `package.json` `version`. It then runs `npm pack --dry-run --ignore-scripts` and writes a ready summary.

It creates no GitHub release, runs no `npm publish` and performs no deployment. `package.json` keeps
`"private": true`, so npm would refuse a publish anyway.

The real-daemon gate workflow is held in PR #3 pending repository workflow permission; until it lands, the
real-daemon set is run locally before a release (command below) and its counts are recorded in the release notes.
The telepty source tree used must contain the telepty#108 fix for RC5 to pass; the held CI gate's pin (`e86f414`)
predates it.

```
TELESESSION_TEST_TELEPTY_DIR=<telepty source tree> node --test test/real-daemon-restart.test.js test/transport-telepty.test.js test/mcp.test.js
```

## Configured versus actually run

These workflow files only **configure** CI. A pass exists only once a run on GitHub shows green for the
specific commit. Committing these files does not:

- make the checks required. That needs branch protection or a ruleset on `main` that requires the `unit (…)`
  and `package dry-run` checks; this repository does not set that up;
- guarantee that a tag was verified before someone pushed or used it. The release check reports, it does not block.

## Lockfile

CI requires `package-lock.json`, because `npm ci` refuses to run without it.

### How the lock was produced

The lock (v3) was **derived deterministically and offline**, not resolved by npm against the registry. The source
was the verified telepty `package-lock.json` (sha256 `9b07cbb07d6f7b52c5547987535a0fde26bf72d15131bf23517954e7b5308863`).

- It starts from the roots `@modelcontextprotocol/sdk` and `zod`, which the source lock pins at `1.29.0` and `3.25.76`.
- It follows `dependencies`, `optionalDependencies` and non-optional `peerDependencies`, resolving each name the way
  node_modules nesting resolves it. Every retained edge is checked against its semver range.
- Optional peers are not added: `@cfworker/json-schema` is absent, and `ajv` is already a regular dependency.
- Each package entry is copied verbatim: `version`, `resolved`, `integrity`, `license`, `engines` and every other field.
- Telepty-only roots and dev packages are left out.
- The root entry mirrors `package.json`: name, version, license, the unchanged ranges `^1.26.0` and `^3.24.0`,
  both bins, and engines. npm does not record `private` in lockfiles.

The result is 91 packages plus the root. Every `resolved` URL is on `https://registry.npmjs.org/`, every entry has a
sha512 `integrity`, and there are no install scripts and no os/cpu restrictions. Running the derivation twice gives
byte-identical output.

npm 11.6.2 accepts the lock offline with an empty cache and fetches nothing (`up to date`). That run used an empty
user/global npmrc:

```
npm install --package-lock-only --offline --ignore-scripts --no-audit --no-fund
```

Its only rewrite was to add a `"peer": true` flag to `express`, `hono` and `zod`. npm recomputes these flags on load,
and the telepty source lock does not carry them.

### Limits

- The real install check is the hosted `npm ci` run. Nothing was installed locally.
- The 91 packages include the SDK's full runtime dependency set: express, hono, jose, cors, eventsource and others.
  The earlier hand-assembled telesession bundle shipped only 14 of these. The 14 match exactly on
  version/resolved/integrity, but the other 77 were never in that bundle.

## Publishing prerequisites (not done by CI)

Before any npm publish, someone must:

1. decide to remove `"private": true`;
2. set up npm credentials or trusted publishing. No workflow here has them, and `id-token: write` is not granted;
3. add a separate, reviewed publish workflow gated on `release-check.yml`;
4. verify the real-daemon, Dot/꼬마, native PTY and restart paths outside this unit matrix.
