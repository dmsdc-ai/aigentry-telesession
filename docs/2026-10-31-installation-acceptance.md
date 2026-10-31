# Linux installation acceptance and release boundary

Consumer uncertainty repairs were committed locally at5dd2583 on isolated branch
fix/telepty-uncertain-http. This follow-up makes the install/startup path reviewable
without touching the original checkout, installed runtime or remote repositories.
It is an installable local stdio candidate, not a claim of a perfect remote product.

## Concrete fixes

- Actual entrypoint tests reproduced help/version failing as CONFIG_TARGETS_INVALID,
  and unknown args being ignored before state/MCP initialization. `--help`, `-h`
  and `--version` now exit before configuration/state startup; other args refuse
  with sanitized ARGS_UNEXPECTED. Bare serving semantics remain unchanged.
- Actual npm pack inspection reproduced the missing API-CONTRACT-TELESESSION.md
  referenced by README. It is now included. The layout test verifies both bins,
  runtime modules and documentation, while excluding dependencies and test fixtures.
- README/install/status distinguish current Linux evidence, capability prerequisites,
  private stdio hosting, operator configuration, durable/unknown behavior and native/
  gateway limits. Existing historical status is preserved rather than relabeled.
- CI unit command includes the startup/layout regressions; CI pack checks the actual
  archive file list. No hosted CI was triggered. The installed-artifact acceptance
  runner is checked in under test-support for maintainers, not shipped as runtime.

## Actual installation and runtime evidence

A local npm tarball was installed with `npm install --offline --ignore-scripts
--no-audit --no-fund --prefix <private-temp-prefix> <tarball>`. A separate temporary
cache was seeded only from already cached public registry dependencies selected
by the lockfile:271 entries,34,398,887 bytes. Metadata was restricted to public
cache headers, with no authentication/user configuration copied. No network was
used and no existing cache, global installation or credentials were changed.

The resulting package, MCP SDK and zod are real directories under the new prefix,
not developer source symlinks; an independent reviewer checked lstat and realpath.
The actual installed executable and its own installed SDK were used to verify:

- npm bin shim and help/version; unexpected arguments refuse;
- exactly five MCP tools, health capability prerequisites and allowlisted targets;
- health/list do not create an inbox;
- durable send, stable request-ID dedupe and exactly one observed synthetic target
  delivery in that test;
- transport receipt remains separate from a credential-attributed trusted reply;
- graceful client close deletes only its owned inbox and preserves the target;
- generated fixture token/prompt are absent from state and credentials absent from
  captured stderr.

All effects used private loopback daemons, synthetic keys/token files, temporary
HOME/state and fixture targets. Actual operational registration, Mac/provider and
remote gateway were never involved. A known source-owned private daemon restart
also passed in the consumer suite; no operating service was restarted.

## Checks

Final full source suite: **193 total /190 passed /zero failed /three skipped**,
34.8s; `/tmp/telesession-install-flow-full-20261031.log`.
Exact CI unit command: **105 total /103 passed /zero failed /two skipped**;
`/tmp/telesession-install-unit-20261031.log`.
Skips are native Windows credential/path acceptance and the deliberately incoherent
simulated-win32 credential test over POSIX paths; none is reported as passed.
Independent startup/layout tests3/3 and actual installed five-tool acceptance pass.
Earlier independent uncertainty/durability55/56 passed with one native skip.
Syntax, local documentation links and diff checks pass. No new dependencies were added.

Independent review found two reusable acceptance-runner truthfulness issues:
timeout errors with code=null could be counted as exit0, and lexical prefix alone
could miss symlinked dependencies. Both are corrected using nonzero error handling
and realpath checks. The original successful install evidence was independently
verified as a real installation and did not depend on either edge case.

Logs: `/tmp/telesession-install-entrypoints-green-20261031.log`,
`/tmp/telesession-installed-acceptance-20261031.log`,
`/tmp/telesession-portable-installed-acceptance-20261031.log`,
`/tmp/telesession-independent-install-final.log`,
`/tmp/telesession-independent-installed-acceptance.log`.
The final reviewed artifact SHA/source/dependency versions belong in the external
artifact manifest, not inside its own tarball where that would be self-referential.

## Posting/operational prerequisites — still not performed

| Surface | Exact target / state |
|---|---|
| Source | dmsdc-ai/aigentry-telesession, isolated local branch only; no push/PR/tag. |
| Registry | Current package @dmsdc-ai/telesession@0.1.0, private:true. Registry account, final new version, dist-tag/access and publication authorization are not resolved; private was not removed. |
| Telepty | Tested local runtime source b842f0c (plus later report-only commit). Observed installed0.9.1 lacks required capabilities; no replacement/restart authorized or performed. |
| Gateway | Package provides stdio only, no HTTP/SSE hosting/enrollment. The observed remote429 was not retried or resolved;404 origin remains unconfirmed. |
| Native environments | Linux Node20.20.0/npm10.8.2 tested. Actual macOS/Windows, current Dot/Mac/provider remain unverified; Windows durable credential persistence is unsupported. |
| Security scan | Historical external product scan remains pending; no source-uploading scan, TLS bypass or security-policy change was performed. |

These are material gates to an installation that works on the user's complete
remote route. Local install success must not be presented as resolving them.
No service/network/security/credential setting was changed, no existing sessions
or data were modified, and no external publication, installation or deployment
was performed.
