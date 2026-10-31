# CI and release verification

Three workflows live in `.github/workflows/`. All run on GitHub-hosted runners with a read-only token
(`permissions: contents: read`), use no secrets, check out with `persist-credentials: false`, and never
publish, release or deploy anything.

## `ci.yml` — cross-platform unit CI

Triggers: pushes to `main`, pull requests, `workflow_dispatch`, and `workflow_call` (reused by the release check).

| Job | Runners | What it runs |
|---|---|---|
| `unit` | `ubuntu-latest`, `macos-latest`, `windows-latest` × Node `20.20.0` (`fail-fast: false`, 15 min timeout) | `npm ci --ignore-scripts --no-audit --no-fund`, then `npm run --silent test:unit` |
| `pack` | `ubuntu-latest`, Node `20.20.0` (10 min timeout) | `npm run --silent test:pack` (`test/package-layout.test.js`: `npm pack --dry-run` file-list assertions) |

Pull-request runs for the same ref cancel older ones; `main` pushes run to completion.

Actions are pinned by commit SHA:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` (TAP output, 14 days)

### Exact unit command

`npm run test:unit`, i.e. the explicit file list in `package.json` `scripts.test:unit` (`test/test-runners.test.js`
fails when a test file is named by no runner).

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

Triggers: `workflow_dispatch`, with an optional string input `telepty_ref`, and pushes of tags matching `v*`.

1. `ci` calls `ci.yml` (the full matrix plus pack).
2. `compat-request` reads `telepty_ref`. If it is empty (it always is on tag pushes), compatibility is not
   requested. If it is exactly 40 lowercase hex characters, compatibility is requested. Any other value fails
   the run before any checkout.
3. `compatibility` runs only when compatibility is requested and `ci` passed. It calls `compatibility.yml`
   (`workflow_call`) with that SHA. Because the call goes through `release-check.yml`, the compatibility run
   works on a named branch before `compatibility.yml` exists on the default branch. A `workflow_dispatch`
   workflow cannot run for the first time until it is on the default branch.
4. `release-gate` first checks its preconditions and fails the run if one is not met. A failed precondition
   is never a silent skip:
   - `ci` passed;
   - the request was valid;
   - if compatibility was requested, `compatibility` passed and its verified Telepty HEAD (`telepty_sha`
     output) equals the requested SHA;
   - if compatibility was not requested, `compatibility` was skipped.

   On tag pushes it then checks that the tag equals `v` + `package.json` `version`. It runs
   `npm pack --dry-run --ignore-scripts` and writes a ready summary. The summary names the verified Telepty
   SHA, or says that compatibility was **not requested, not run and not established**.

It creates no GitHub release, runs no `npm publish` and performs no deployment. Since 0.2.0 `package.json`
no longer has `"private": true` and declares `publishConfig.access: "public"`, so npm would **not** refuse a
publish: publication control rests on credentials and the separate authorized publication step.
A passing pack check (`check:pack` dry-run or `test:pack`) proves the tarball file layout only. It
publishes nothing and does not imply that the package is ready or authorized for publication.
No result of this workflow, including a passing compatibility run, authorizes a tag or a publication.

Controller invocation (the candidate branch must contain this `release-check.yml`; `<branch>` is a branch
name, `<sha40>` is the selected Telepty commit):

```
gh workflow run release-check.yml --repo dmsdc-ai/aigentry-telesession --ref <branch> -f telepty_ref=<sha40>
gh run list --repo dmsdc-ai/aigentry-telesession --workflow release-check.yml --branch <branch> --event workflow_dispatch --limit 1 --json databaseId,headSha,status,conclusion
gh run watch <run-id> --repo dmsdc-ai/aigentry-telesession --exit-status
gh run view <run-id> --repo dmsdc-ai/aigentry-telesession --json headSha,conclusion,jobs
gh run download <run-id> --repo dmsdc-ai/aigentry-telesession --pattern 'compatibility-*'
```

Accept a run only if `headSha` is the exact Telesession candidate, its conclusion is `success`, the
`compatibility (…)` jobs ran on all three OSes, and every `provenance.json` shows `telepty.sha` = `<sha40>`.

## `compatibility.yml` — exact-candidate validation against one Telepty commit

Triggers: `workflow_call`, which `release-check.yml` uses (the supported path before this file is on the
default branch), and `workflow_dispatch` (only once the file is on the default branch). Both take the required
input `telepty_ref`. It must be exactly 40 lowercase hex characters, an immutable commit of the public
`dmsdc-ai/aigentry-telepty`. A branch, tag or short SHA is refused before any checkout, and the checked-out
HEAD is compared with the input again afterwards.
- A Telepty tree without `daemon.js` fails the job. So does a full-suite TAP that reports a real-daemon
  suite skipped as `NOTRUN: telepty source not found`.
- The output `telepty_sha` is set only after the HEAD check passes. `release-gate` compares it with the request.

- Matrix: `ubuntu-latest`, `macos-latest`, `windows-latest` × Node `20.20.0`, `fail-fast: false`, 20 min.
- Telesession (this ref) and Telepty (the exact SHA) are checked out read-only into separate directories
  (`persist-credentials: false`). The pinned actions are the same three as `ci.yml`. It has no secrets and
  no login, and it never tags or publishes.
- Both trees run `npm ci --ignore-scripts` from their own lockfiles. The single reviewed exception is
  `npm rebuild node-pty` in the Telepty tree. node-pty is the native PTY addon that Telepty's bridge
  (`cli.js allow`, used by the RC5 restart test) loads, and `--ignore-scripts` skips its binary setup.
  Only node-pty's own scripts run; Telepty's root `postinstall`/`preuninstall` never run.
- `TELESESSION_TEST_TELEPTY_DIR` points at the exact Telepty tree. Gates:
  1. the full `npm test`;
  2. `npm run test:pack`;
  3. Linux/macOS only: `npm pack` of the candidate, an install of that tarball into a fresh private prefix
     (the `docs/install.md` recipe), then `npm run test:installed` with
     `TELESESSION_TEST_INSTALLED_PACKAGE=<prefix>/node_modules/@dmsdc-ai/telesession`.
- A failing gate fails the job. Later gates still run where their inputs exist, so every outcome is
  recorded.
- npm cache, npmrc, child logs, pack output and the install prefix live under the runner's `RUNNER_TEMP`.
  Test fixtures use their own temp HOME and ephemeral loopback daemons. No real user's HOME, data or
  service is used.
- Evidence artifact (14 days): `provenance.json` (Telesession SHA/version, Telepty SHA/version, OS, arch,
  Node, npm, run id), raw `full.tap`, `pack-test.tap`, `pack.json`, `tarball.json` (filename, sha256), the
  tarball, `install.log`, `installed.log`, `node-pty-rebuild.log` and child logs. The job summary lists
  counts per suite and every skipped test by name; skips are never counted as passes.

What it does **not** establish: the cross-host Mac/Linux live communication gate. Both directions
(Mac→Linux request with a matching Linux→Mac ACK, and the reverse) need the exact final candidates on both
hosts, a real Telepty route, actual target session input, a matching semantic ACK and no duplicate
execution. Daemon acceptance alone, `consumption=unknown` or native Codex input API delivery are
insufficient. This gate is mandatory **before Telepty publication**, and it blocks npm publication and any
release tag. GitHub runners cannot provide it.

The real-daemon gate workflow is held in PR #3 pending repository workflow permission; until it lands, the
real-daemon set is run locally before a release (command below) and its counts are recorded in the release notes.
The telepty source tree used must contain the telepty#108 fix for RC5 to pass; the held CI gate's pin (`e86f414`)
predates it.

```
TELESESSION_TEST_TELEPTY_DIR=<telepty source tree> node --test test/real-daemon-restart.test.js test/transport-telepty.test.js test/mcp.test.js
```

The same set is `npm run test:real-daemon`. `test:unit` names every test file that runs without a real daemon
or the MCP SDK (`transport-telepty` too: its real-daemon block is skipped NOTRUN there); `test:e2e` runs the
fake-adapter full-route proof on its own (it is daemon-free, so `test:unit` names it too). `test/test-runners.test.js` fails when a test file is named by none of them.

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
- The root entry mirrors `package.json`: name, version, license, the ranges, the bins and engines. npm does not
  record `private` in lockfiles. Originally the ranges were `^1.26.0` and `^3.24.0` with two bins. In 0.2.0 only
  the root entry was hand-aligned: the ranges were raised to the tested floors `^1.29.0` and `^3.25.76`, and all
  four bins are listed. No package resolution changed.

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

1. confirm the 0.2.0 publication decision (`private` was removed and `publishConfig.access: "public"` added in 0.2.0);
2. set up npm credentials or trusted publishing. No workflow here has them, and `id-token: write` is not granted;
3. apply the existing user publication authority as a separate step after all gates. No automated release tag
   or publish job exists, and none is added in 0.2.0;
4. verify the real-daemon, Dot/꼬마, native PTY and restart paths outside this unit matrix: a green
   `compatibility.yml` run on the exact candidate and Telepty SHA, then the cross-host Mac/Linux live
   communication gate above (before Telepty publication).
