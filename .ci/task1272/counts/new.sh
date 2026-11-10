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
    # Node 20 prints TAP ('# pass N'); Node 26's default spec reporter prints 'ℹ pass N' and skipped rows as
    # '﹣ <title> # NOTRUN: <reason>'. sed -n exits 0 when nothing matches; CR is stripped on read only.
    sum=$(tr -d '\r' < "$f" | sed -n -E 's/^(# |ℹ )(tests|suites|pass|fail|cancelled|skipped|todo) ([0-9]+)$/- \2 \3/p')
    if [ -n "$sum" ]; then printf '%s\n' "$sum"; else echo "- no TAP (#) or spec (ℹ) summary line found"; fi
    echo "Skipped (NOT counted as passed):"
    skips=$(tr -d '\r' < "$f" | sed -n -E '/# SKIP|^ *﹣ /p' | sed -E 's/^ +//; s/^/- /')
    if [ -n "$skips" ]; then printf '%s\n' "$skips"; else echo "- none"; fi
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
    pass=$(tr -d '\r' < "$f" | sed -n -E 's/^(# |ℹ )pass ([0-9]+)$/\2/p' | tail -n 1)
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
