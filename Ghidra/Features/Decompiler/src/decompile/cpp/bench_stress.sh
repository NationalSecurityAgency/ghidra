#!/bin/bash
# Intra-function-parallel stress benchmark.
#
# Repeats the datatests corpus N times per timed invocation to amortize
# JIT/cache/startup costs and produce stable relative timings across the
# six dispatch modes (serial, path1, path3, path4 with/without the safe
# blocklist).  Datatests is small — average 18ms/function over 82 small
# functions — so a single pass at 1.5s is too noisy to distinguish 5%
# effects.  Looping 20× per invocation gives ~30s/run which resolves
# better, at the cost of pretending each function appears 20× in the
# corpus.  Relative ordering across modes is preserved.
#
# Usage:  ./bench_stress.sh [RUNS] [ITERS]
# Defaults: RUNS=3, ITERS=20

set -u
RUNS=${1:-${RUNS:-3}}
ITERS=${2:-${ITERS:-20}}
BIN=./decomp_test_dbg
DATATESTS=../datatests

SAFE_BLOCKLIST="doublestore,shiftand,boolzext,threewaycomp,trivialshift,rightshiftand,concatshift,leftright,concatleftshift,highorderand,andcommute,signnearmult,positivediv,slesstoless,zextsless,piecepathology,orpredicate,orcollapse,humptyor,ptrsubcharconstant,floatcast,switchsingle,less2zero,extensionpush,xorswap,floatsigncleanup"

clear_env() {
  unset DECOMP_INTRA_WORKERS DECOMP_INTRA_MINOPS
  unset DECOMP_INTRA_BLOCK_PARALLEL DECOMP_INTRA_TRUE_PARALLEL DECOMP_INTRA_RULE_BLOCKLIST
  unset DECOMP_INTRA_RULE_STATS DECOMP_INTRA_SCOPE_STATS DECOMP_INTRA_GRAPH_STATS
}

run_mode() {
  local label="$1"
  local times=()
  local total=0
  local r
  for r in $(seq 1 $RUNS); do
    local start=$(date +%s.%N)
    local i
    for i in $(seq 1 $ITERS); do
      "$BIN" -usesleighenv -path "$DATATESTS" datatests > /dev/null 2>&1 || true
    done
    local end=$(date +%s.%N)
    local elapsed=$(echo "$end - $start" | bc -l)
    times+=("$(printf '%.2f' "$elapsed")")
  done
  # Sort to find median.
  local sorted=($(printf '%s\n' "${times[@]}" | sort -n))
  local mid=$(( ${#sorted[@]} / 2 ))
  local median=${sorted[$mid]}
  # Sum for avg.
  local sum=0; for t in "${times[@]}"; do sum=$(echo "$sum + $t" | bc -l); done
  local avg=$(printf '%.2f' "$(echo "scale=3; $sum / $RUNS" | bc -l)")
  printf "%-26s %s  median=%ss avg=%ss\n" "$label" "${times[*]}" "$median" "$avg"
}

if [ ! -x "$BIN" ]; then echo "error: $BIN not built" >&2; exit 1; fi

echo "==== stress bench: ITERS=$ITERS iterations × RUNS=$RUNS runs/mode ===="
echo "(each iteration = one full pass over $(ls $DATATESTS/*.xml | wc -l) datatest functions)"

clear_env
run_mode "serial baseline"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1
run_mode "path1 W=4"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1
run_mode "path3 W=4"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1
run_mode "path4 W=4"

clear_env
export DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_mode "serial + bl"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_mode "path1 W=4 + bl"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_mode "path3 W=4 + bl"

clear_env
export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
run_mode "path4 W=4 + bl"

clear_env
export DECOMP_INTRA_WORKERS=8 DECOMP_INTRA_MINOPS=1
run_mode "path1 W=8"

clear_env
export DECOMP_INTRA_WORKERS=8 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1
run_mode "path3 W=8"

clear_env
export DECOMP_INTRA_WORKERS=8 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1
run_mode "path4 W=8"
