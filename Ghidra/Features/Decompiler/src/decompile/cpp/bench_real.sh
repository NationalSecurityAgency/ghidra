#!/bin/bash
# Real-corpus intra-parallel benchmark.
#
# Runs decomp_opt on a directory of XML savefiles (one function each, in
# the xml_savefile format produced by DecompileDebug.java).  Each function
# is restored, decompiled, and the architecture is cleared between
# functions to mimic the per-function lifecycle of the Java-driven path
# (without the JVM/pipe overhead).
#
# Usage:    ./bench_real.sh [corpus_dir] [runs]
# Defaults: corpus_dir=/tmp/bench_corpus/xml, runs=3
#
# The script generates a single driver script that loops over every XML
# in the corpus and feeds it once to decomp_opt; per-mode wall time is
# the dominant signal.

set -u
CORPUS=${1:-/tmp/bench_corpus/xml}
RUNS=${2:-${RUNS:-3}}
BIN=./decomp_opt
DRIVER=/tmp/bench_real_driver.dec

if [ ! -x "$BIN" ]; then echo "error: $BIN not built" >&2; exit 1; fi
if [ ! -d "$CORPUS" ]; then echo "error: $CORPUS not found" >&2; exit 1; fi

# Need SLEIGHHOME for decomp_opt to find sleigh data.  Defaults to the
# /srv/project layout; override via env when running on a different host.
: "${SLEIGHHOME:=/srv/project/ghidra/build/ghidra_install/ghidra_12.2_DEV}"
export SLEIGHHOME

# Build the driver script that processes every XML once.
{
  for xml in "$CORPUS"/*.xml; do
    name=$(grep -m1 'xml_savefile name=' "$xml" | sed 's/.*name="\([^"]*\)".*/\1/')
    if [ -z "$name" ]; then continue; fi
    echo "restore $xml"
    echo "load function $name"
    echo "decompile"
    echo "clear architecture"
  done
  echo "quit"
} > "$DRIVER"

NUM_XMLS=$(ls "$CORPUS"/*.xml 2>/dev/null | wc -l)

SAFE_BLOCKLIST="doublestore,shiftand,boolzext,threewaycomp,trivialshift,rightshiftand,concatshift,leftright,concatleftshift,highorderand,andcommute,signnearmult,positivediv,slesstoless,zextsless,piecepathology,orpredicate,orcollapse,humptyor,ptrsubcharconstant,floatcast,switchsingle,less2zero,extensionpush,xorswap,floatsigncleanup"

clear_env() {
  unset DECOMP_INTRA_WORKERS DECOMP_INTRA_MINOPS
  unset DECOMP_INTRA_BLOCK_PARALLEL DECOMP_INTRA_TRUE_PARALLEL DECOMP_INTRA_RULE_BLOCKLIST
}

run_mode() {
  local label="$1"
  local times=()
  local r
  for r in $(seq 1 $RUNS); do
    local start=$(date +%s.%N)
    "$BIN" -i "$DRIVER" < /dev/null > /dev/null 2>&1 || true
    local end=$(date +%s.%N)
    times+=("$(printf '%.2f' "$(echo "$end - $start" | bc -l)")")
  done
  local sum=0; for t in "${times[@]}"; do sum=$(echo "$sum + $t" | bc -l); done
  local avg=$(printf '%.2f' "$(echo "scale=3; $sum / $RUNS" | bc -l)")
  printf "%-26s %s  avg=%ss\n" "$label" "${times[*]}" "$avg"
}

echo "==== real-corpus bench: $NUM_XMLS functions × RUNS=$RUNS ===="
echo "(corpus: $CORPUS)"

clear_env;                                                                                         run_mode "serial baseline"
clear_env; export DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST";                                   run_mode "serial + bl"
clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1;                                    run_mode "path1 W=4"
clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"; run_mode "path1 W=4 + bl"
clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1;      run_mode "path3 W=4"
clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"; run_mode "path3 W=4 + bl"
clear_env; export DECOMP_INTRA_WORKERS=8 DECOMP_INTRA_MINOPS=1;                                    run_mode "path1 W=8"
clear_env; export DECOMP_INTRA_WORKERS=8 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1;      run_mode "path3 W=8"
clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1; run_mode "path4 W=4"
clear_env; export DECOMP_INTRA_WORKERS=8 DECOMP_INTRA_MINOPS=1 DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_TRUE_PARALLEL=1; run_mode "path4 W=8"
