#!/usr/bin/env sh
set -eu

ROOT="$(pwd)"
TMP_BASE="/tmp/ls2l-base"
TMP_OPT="/tmp/ls2l-opt"

rm -rf "$TMP_BASE" "$TMP_OPT"
mkdir -p "$TMP_BASE" "$TMP_OPT"

# Baseline from committed HEAD
mkdir -p "$TMP_BASE/src"
git archive HEAD src | tar -x -C "$TMP_BASE"

# Optimized from current working tree
cp -R "$ROOT/src" "$TMP_OPT/src"

LOG_COUNT="${1:-50000}"
WORKERS="${2:-8}"
TIMEOUT_S="${3:-25}"
LOKI_DELAY_MS="${4:-0.2}"

echo "BASELINE"
python /work/tests/bench/e2e_single.py \
  --code-dir "$TMP_BASE/src" \
  --log-count "$LOG_COUNT" \
  --workers "$WORKERS" \
  --timeout-s "$TIMEOUT_S" \
  --loki-delay-ms "$LOKI_DELAY_MS"

echo "OPTIMIZED"
python /work/tests/bench/e2e_single.py \
  --code-dir "$TMP_OPT/src" \
  --log-count "$LOG_COUNT" \
  --workers "$WORKERS" \
  --timeout-s "$TIMEOUT_S" \
  --loki-delay-ms "$LOKI_DELAY_MS"
