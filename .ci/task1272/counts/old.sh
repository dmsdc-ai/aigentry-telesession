set -uo pipefail
COMPAT="${COMPAT:-$RUNNER_TEMP/compat}"
status=0
{
  echo "### compatibility: $RUNNER_OS / Node $(node --version)"
  [ -f "$COMPAT/provenance.json" ] && { echo '```json'; cat "$COMPAT/provenance.json"; echo '```'; }
  for t in full pack-test profile; do
    f="$COMPAT/$t.tap"
    echo "#### $t"
    if [ ! -s "$f" ]; then echo "- no TAP output (step not run or failed before output)"; continue; fi
    grep -E '^# (tests|suites|pass|fail|cancelled|skipped|todo) ' "$f" | sed 's/^# /- /'
    echo "Skipped (NOT counted as passed):"
    grep -E '# SKIP' "$f" | sed -E 's/^ +//; s/^/- /' || echo "- none"
  done
  echo "#### outcomes"
  echo "- full: ${FULL:-not run}; test:pack: ${PACKTEST:-not run}; installed: ${INSTALLED:-not run (Windows: not part of this gate)}"
  echo "- required S-R1 profile rows: ${PROFILE:-not run}; Darwin authority reader: ${DARWIN_READER:-not run}"
  [ "$RUNNER_OS" = Windows ] && echo "- Windows: profile mode is refused there (configured-mode refusal rows only); S-R1 is NOT run and NOT claimed"
  [ -f "$COMPAT/darwin-reader.txt" ] && { echo '```'; cat "$COMPAT/darwin-reader.txt"; echo '```'; }
  [ -f "$COMPAT/tarball.json" ] && { echo '```json'; cat "$COMPAT/tarball.json"; echo '```'; }
} >> "$GITHUB_STEP_SUMMARY"
for t in full pack-test; do
  f="$COMPAT/$t.tap"
  if [ -s "$f" ]; then
    pass=$(sed -n -E 's/^# pass ([0-9]+)$/\1/p' "$f" | tail -n 1)
    if [ "${pass:-0}" -eq 0 ]; then echo "::error::$t: no passing tests recorded"; status=1; fi
  fi
done
# Issue #16: on Linux/macOS the required profile rows must have run and passed in this attempt.
if [ "$RUNNER_OS" != Windows ] && [ "${PROFILE:-}" != success ]; then
  echo "::error::required S-R1 profile rows: ${PROFILE:-not run}"; status=1
fi
# A real-daemon suite skipped for a missing Telepty tree is not compatibility evidence.
if [ -s "$COMPAT/full.tap" ] && grep -q 'NOTRUN: telepty source not found' "$COMPAT/full.tap"; then
  echo "::error::full: real-daemon suites skipped (telepty source not found)"; status=1
fi
exit $status
