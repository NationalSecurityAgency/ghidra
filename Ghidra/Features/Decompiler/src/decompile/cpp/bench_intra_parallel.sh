#!/bin/bash
# Path 1/2/3 intra-function-parallel decompiler micro-benchmark.
#
# Runs the datatests suite 5 times under each dispatch configuration and
# reports per-run wall times plus the average.  Intended as a regression
# baseline; datatests-only is too small to show real parallel speedup
# (threading overhead dominates), but the numbers must remain stable.
#
# Usage:   ./bench_intra_parallel.sh
# Run from the decompiler cpp dir (Ghidra/Features/Decompiler/src/decompile/cpp).
# Requires decomp_test_dbg built (make decomp_test_dbg) and ../datatests present.

set -u
RUNS=${RUNS:-5}
BIN=./decomp_test_dbg
DATATESTS=../datatests

# 26-rule never-fires safe blocklist measured on top30 libc x86_64 datatests
# aggregate.  Two more never-fires rules (signform2, subright) were flagged
# but excluded after bisect since they fire on at least one individual test.
SAFE_BLOCKLIST="doublestore,shiftand,boolzext,threewaycomp,trivialshift,rightshiftand,concatshift,leftright,concatleftshift,highorderand,andcommute,signnearmult,positivediv,slesstoless,zextsless,piecepathology,orpredicate,orcollapse,humptyor,ptrsubcharconstant,floatcast,switchsingle,less2zero,extensionpush,xorswap,floatsigncleanup"

run_bench() {
  local label="$1"
  local times=()
  local r
  for r in $(seq 1 $RUNS); do
    local tmp
    tmp=$(mktemp)
    /usr/bin/time -f "%e" -o "$tmp" "$BIN" -usesleighenv -path "$DATATESTS" datatests > /dev/null 2>&1 || true
    # /usr/bin/time writes the "Command exited with non-zero status N" line
    # alongside %e when the child exits non-zero (4 stack-spill datatests
    # currently fail across all dispatch modes — pre-existing baseline).
    # Grab only the numeric time line.
    times+=("$(grep -E '^[0-9]+(\.[0-9]+)?$' "$tmp" | head -1)")
    rm -f "$tmp"
  done
  local sum=0
  local t
  for t in "${times[@]}"; do
    sum=$(echo "$sum + $t" | bc -l)
  done
  local avg
  avg=$(echo "scale=3; $sum / $RUNS" | bc -l)
  printf "%-22s %s avg=%ss\n" "$label" "${times[*]}" "$avg"
}

if [ ! -x "$BIN" ]; then
  echo "error: $BIN not found; run 'make decomp_test_dbg' first" >&2
  exit 1
fi
if [ ! -d "$DATATESTS" ]; then
  echo "error: $DATATESTS not found" >&2
  exit 1
fi

# Strip any inherited intra-parallel env so each run starts clean, then export per-mode.
clear_env() {
  unset DECOMP_INTRA_WORKERS DECOMP_INTRA_MINOPS
  unset DECOMP_INTRA_BLOCK_PARALLEL DECOMP_INTRA_TRUE_PARALLEL DECOMP_INTRA_RULE_BLOCKLIST
  unset DECOMP_INTRA_RULE_STATS DECOMP_INTRA_SCOPE_STATS DECOMP_INTRA_GRAPH_STATS
}

echo "==== datatests intra-parallel benchmark, $RUNS runs/mode ===="
clear_env
run_bench "serial (baseline)"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1
run_bench "path1 W=4"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1
run_bench "path3 W=4"

clear_env
export DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_bench "serial + blocklist"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_bench "path1 W=4 + bl"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_bench "path3 W=4 + bl"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1
run_bench "path4 W=4 (experimental)"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_bench "path4 W=4 + bl"
