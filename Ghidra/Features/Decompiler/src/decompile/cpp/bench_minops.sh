#!/bin/bash
# Sweep DECOMP_INTRA_MINOPS to find the threshold where intra-parallel
# starts paying off on the libcrypto fat-function corpus.  All modes use
# Path 3 + blocklist at W=4.

set -u
CORPUS=${1:-/tmp/bench_corpus/xml}
RUNS=${2:-${RUNS:-3}}
BIN=./decomp_opt
DRIVER=/tmp/bench_real_driver.dec
export SLEIGHHOME=/srv/project/ghidra/build/ghidra_install/ghidra_12.2_DEV
SAFE_BLOCKLIST="doublestore,shiftand,boolzext,threewaycomp,trivialshift,rightshiftand,concatshift,leftright,concatleftshift,highorderand,andcommute,signnearmult,positivediv,slesstoless,zextsless,piecepathology,orpredicate,orcollapse,humptyor,ptrsubcharconstant,floatcast,switchsingle,less2zero,extensionpush,xorswap,floatsigncleanup"

{
  for xml in "$CORPUS"/*.xml; do
    name=$(grep -m1 'xml_savefile name=' "$xml" | sed 's/.*name="\([^"]*\)".*/\1/')
    [ -z "$name" ] && continue
    echo "restore $xml"
    echo "load function $name"
    echo "decompile"
    echo "clear architecture"
  done
  echo "quit"
} > "$DRIVER"

NUM_XMLS=$(ls "$CORPUS"/*.xml 2>/dev/null | wc -l)

run_mode() {
  local label="$1"
  local times=()
  for r in $(seq 1 $RUNS); do
    local start=$(date +%s.%N)
    "$BIN" -i "$DRIVER" < /dev/null > /dev/null 2>&1 || true
    local end=$(date +%s.%N)
    times+=("$(printf '%.2f' "$(echo "$end - $start" | bc -l)")")
  done
  local sum=0; for t in "${times[@]}"; do sum=$(echo "$sum + $t" | bc -l); done
  local avg=$(printf '%.2f' "$(echo "scale=3; $sum / $RUNS" | bc -l)")
  printf "%-30s %s  avg=%ss\n" "$label" "${times[*]}" "$avg"
}

clear_env() {
  unset DECOMP_INTRA_WORKERS DECOMP_INTRA_MINOPS
  unset DECOMP_INTRA_BLOCK_PARALLEL DECOMP_INTRA_TRUE_PARALLEL DECOMP_INTRA_RULE_BLOCKLIST
}

echo "==== MINOPS sweep: $NUM_XMLS functions × RUNS=$RUNS, all with bl+W=4 ===="

clear_env; export DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST";                                                          run_mode "serial + bl"

for minops in 1 100 500 1000 2000 5000; do
  clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=$minops DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
  run_mode "path1 W=4 + bl MINOPS=$minops"
done
for minops in 1 100 500 1000 2000 5000; do
  clear_env; export DECOMP_INTRA_WORKERS=4 DECOMP_INTRA_MINOPS=$minops DECOMP_INTRA_BLOCK_PARALLEL=1 DECOMP_INTRA_RULE_BLOCKLIST="$SAFE_BLOCKLIST"
  run_mode "path3 W=4 + bl MINOPS=$minops"
done
