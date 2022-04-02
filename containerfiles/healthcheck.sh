#!/bin/sh

set -eu

if ! ghidra-server status 2> '/dev/null' | grep '^Running.*[[:space:]]:[[:space:]]true$'; then
	echo 'Failed to determine Ghidra server running status'
	exit 1
fi

exit 0
