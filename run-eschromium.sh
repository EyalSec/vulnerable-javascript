#!/usr/bin/env bash
#
# Drive every catalogued trigger under es-chromium and report which flows were
# actually detected.
#
# The catalogue in catalog.js is the input, so this harness and the operator map
# at catalog.html can never disagree about what this app claims to demonstrate.
#
# Usage
#   ./run-eschromium.sh /path/to/es-chromium                       # against the local serve.py
#   ./run-eschromium.sh /path/to/es-chromium http://127.0.0.1:8000/
#   ./run-eschromium.sh /path/to/es-chromium https://eyalsec.github.io/vulnerable-javascript/
#
# Environment
#   ESC_TIMEOUT   seconds to give each page, default 18
#   ESC_FLAGS     extra flags for the browser, default "--no-sandbox --disable-gpu"
#   ESC_OUT       directory for the raw per-trigger logs, default ./.esc-runs
#
# Two things about es-chromium that this script relies on, both of which will
# bite you if you drive it by hand instead:
#
#   * ES2_CHROMIUM_TEST_SINK=1 prints detections as ESEVENT lines and needs no
#     dashboard and no token.
#   * The browser stays open like a browser and never exits on its own, so every
#     run is bounded with timeout and a non-zero exit from it is normal.
#
set -uo pipefail
cd "$(dirname "$0")"

ESC="${1:-}"
BASE="${2:-http://127.0.0.1:8000/}"
TIMEOUT="${ESC_TIMEOUT:-18}"
FLAGS="${ESC_FLAGS:---no-sandbox --disable-gpu}"
OUT="${ESC_OUT:-.esc-runs}"

if [ -z "$ESC" ] || [ ! -x "$ESC" ]; then
  echo "usage: $0 /path/to/es-chromium [base-url]" >&2
  echo "" >&2
  echo "es-chromium is delivered through the EyalSec dashboard; see" >&2
  echo "https://github.com/EyalSec/es-chromium" >&2
  exit 2
fi
case "$BASE" in */) ;; *) BASE="$BASE/" ;; esac

command -v python3 >/dev/null || { echo "python3 is required to read catalog.js" >&2; exit 2; }
mkdir -p "$OUT"

# es-chromium wraps the attacker controlled span of a repr in two invisible
# private use characters, U+E000 and U+E001, so a reader can see exactly which
# characters were tainted rather than only that the value was. They are real
# characters in the output, so a payload that straddles the boundary will not
# match as plain text. Strip them before comparing.
#
#   repr=<U+E000>https://example.com/v1/<U+E001>summary.json
#
SENTINEL_OPEN=$'\ue000'
SENTINEL_CLOSE=$'\ue001'
strip_sentinels() { sed "s/$SENTINEL_OPEN//g; s/$SENTINEL_CLOSE//g"; }

# ---------------------------------------------------------------------------
# Pull the catalogue out of catalog.js. The array is authored as strict JSON
# precisely so this works without a JavaScript engine.
# ---------------------------------------------------------------------------
read_catalog() {
  python3 - "$1" <<'PY'
import json, sys
src = open(sys.argv[1], encoding="utf-8").read()
start = src.index("const CATALOG =")
start = src.index("[", start)
end = src.rindex("]", start) + 1
rows = json.loads(src[start:end])
for r in rows:
    expected = "1" if r.get("expected", True) else "0"
    print("\t".join([r["id"], r["trigger"], r["where"], r["sink"],
                     r["source"], expected, r["marker"]]))
PY
}

CAT="$(read_catalog catalog.js)" || { echo "could not parse catalog.js" >&2; exit 2; }
TOTAL=$(printf '%s\n' "$CAT" | grep -c .)

# Unique triggers: several rows deliberately share one URL, because one feature
# can reach two sinks. Running the shared trigger once is enough.
TRIGGERS=$(printf '%s\n' "$CAT" | cut -f2 | awk '!seen[$0]++')
NTRIG=$(printf '%s\n' "$TRIGGERS" | grep -c .)

echo "es-chromium : $ESC"
echo "target      : $BASE"
echo "catalogue   : $TOTAL flows across $NTRIG page loads"
echo "per load    : ${TIMEOUT}s (the browser does not self-exit; timeout is expected)"
echo

# ---------------------------------------------------------------------------
# Drive each trigger.
# ---------------------------------------------------------------------------
i=0
while IFS= read -r trig; do
  [ -n "$trig" ] || continue
  i=$((i + 1))
  safe=$(printf '%s' "$trig" | tr -c 'A-Za-z0-9._-' '_')
  printf '  [%2d/%2d] %s\n' "$i" "$NTRIG" "$trig"

  # A fresh profile per load. Three features deliberately read from cookies and
  # from web storage, so a shared profile would carry one trigger's state into
  # the next run and report detections the trigger did not cause. Storage still
  # persists *within* a load, which is what those three need.
  prof=$(mktemp -d "${TMPDIR:-/tmp}/esc-profile.XXXXXX")
  ES2_CHROMIUM_TEST_SINK=1 timeout "$TIMEOUT" \
    "$ESC" $FLAGS --user-data-dir="$prof" "${BASE}${trig}" > "$OUT/$safe.log" 2>&1
  rm -rf "$prof"
done <<< "$TRIGGERS"

echo
printf '%-22s %-26s %-22s %s\n' "FLOW" "SINK" "SOURCE" "RESULT"
printf '%s\n' "----------------------------------------------------------------------------------------"

pass=0
fail=0
known=0
closed=0
missing=""
newly=""
expected_total=0

while IFS=$'\t' read -r id trig where sink source expected marker; do
  [ -n "$id" ] || continue
  safe=$(printf '%s' "$trig" | tr -c 'A-Za-z0-9._-' '_')
  log="$OUT/$safe.log"

  # A detection is an ESEVENT that names this sink, carries a real origin, AND
  # carries this row's payload. Matching the sink alone is not enough: several
  # rows share a sink, and one flow (the widget) fires on every load with benign
  # content, so a sink-only match reports rows that never actually fired.
  if grep -a "^ESEVENT" "$log" 2>/dev/null \
       | grep -av "origin=null" \
       | grep -aF "where=$where " \
       | strip_sentinels \
       | grep -aqF "$marker"; then
    seen=yes
  else
    seen=no
  fi

  if [ "$expected" = "1" ]; then
    expected_total=$((expected_total + 1))
    if [ "$seen" = yes ]; then
      printf '%-22s %-26s %-22s %s\n' "$id" "$sink" "$source" "detected"
      pass=$((pass + 1))
    else
      printf '%-22s %-26s %-22s %s\n' "$id" "$sink" "$source" "NOT DETECTED"
      fail=$((fail + 1))
      missing="$missing $id"
    fi
  else
    # A catalogued gap. Exploitable, and known not to be reported.
    if [ "$seen" = yes ]; then
      printf '%-22s %-26s %-22s %s\n' "$id" "$sink" "$source" "NOW DETECTED (gap closed)"
      closed=$((closed + 1))
      newly="$newly $id"
    else
      printf '%-22s %-26s %-22s %s\n' "$id" "$sink" "$source" "known gap, not detected"
      known=$((known + 1))
    fi
  fi
done <<< "$CAT"

echo
echo "detected $pass of $expected_total flows this build is expected to report"
echo "known gaps still open: $known (exploitable and deliberately not claimed)"

if [ "$closed" -gt 0 ]; then
  echo
  echo "GAP CLOSED:$newly"
  echo "This build reports a flow the catalogue lists as a known non-detection."
  echo "That is good news, and it means catalog.js and the README are now stale."
fi

if [ "$fail" -gt 0 ]; then
  echo
  echo "not detected:$missing"
  echo "A flow that stops firing belongs in the README's known non-detections"
  echo "section, with what was observed. Raw logs are under $OUT/."
  exit 1
fi
echo "raw logs: $OUT/"
