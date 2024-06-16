#!/bin/bash
#
# Command-line script for starting GhidraGo

# launch mode  (fg, bg, debug, debug-suspend, debug-suspend-launcher)
LAUNCH_MODE=fg

# Resolve symbolic link if present and get the directory this script lives in.
# NOTE: "readlink -f" is best but works on Linux only, "readlink" will only work if your PWD
# contains the link you are calling (which is the best we can do on macOS), and the "echo" is the 
# fallback, which doesn't attempt to do anything with links.
SCRIPT_FILE="$(readlink -f "$0" 2>/dev/null || readlink "$0" 2>/dev/null || echo "$0")"
SCRIPT_DIR="${SCRIPT_FILE%/*}"

# Launch Filesystem Conversion
"${SCRIPT_DIR}"/../launch.sh $LAUNCH_MODE jdk GhidraGo "" "" ghidra.GhidraGo "$@"
