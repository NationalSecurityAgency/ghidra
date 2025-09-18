## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
. $MODULE_Debugger_rmi_trace_HOME/data/support/setuputils.sh

add-gdb-init-args() {
	args+=(-q)
	args+=(-ex "set pagination off")
	args+=(-ex "set confirm off")
	args+=(-ex "show version")
	args+=(-ex "python import ghidragdb")
	args+=(-ex "python if not 'ghidragdb' in locals(): exit(253)")
	args+=(-ex "set architecture $OPT_ARCH")
	args+=(-ex "set endian $OPT_ENDIAN")
}

add-gdb-image-and-args() {
	target_image=$1
	shift

	if [ -n "$target_image" ]; then
		args+=(-ex "file '$target_image'")
	fi
	if [ "$#" -ne 0 ]; then
		local qargs
		printf -v qargs '%q ' "$@"
		args+=(-ex "set args $qargs")
	fi
}

add-gdb-inferior-tty() {
	# Ghidra will leave TTY_TARGET empty when OPT_EXTRA_TTY is false.
	# Gdb takes empty to mean the same terminal.
	args+=(-ex "set inferior-tty $TTY_TARGET")
}

add-gdb-connect-and-sync() {
	address=$1

	args+=(-ex "ghidra trace connect '$address'")
	args+=(-ex "ghidra trace start")
	args+=(-ex "ghidra trace sync-enable")
}

add-gdb-start-if-image() {
	target_image=$1

	if [ -n "$target_image" ]; then
		args+=(-ex "$OPT_START_CMD")
	fi
}

add-gdb-tail-args() {
	args+=(-ex "set confirm on")
#	args+=(-ex "set pagination on")
}

compute-gdb-usermode-args() {
	target_image=$1
	rmi_address=$2
	shift
	shift

	args+=("$OPT_GDB_PATH")
	add-gdb-init-args
	add-gdb-image-and-args "$target_image" "$@"
	add-gdb-inferior-tty
	add-gdb-connect-and-sync "$rmi_address"
	add-gdb-start-if-image "$target_image"
	add-gdb-tail-args
}

compute-gdb-wine-args() {
	target_image=$1
	rmi_address=$2
	shift
	shift

	args+=("$OPT_GDB_PATH")
	add-gdb-init-args
	add-gdb-image-and-args "$OPT_WINE_PATH" "$target_image" "$@"
	add-gdb-inferior-tty
	gdb+=(-ex "starti")
	gdb+=(-ex "ghidra wine run-to-image '$target_image'")
	add-gdb-connect-and-sync "$rmi_address"
	gdb+=(-ex "ghidra trace sync-synth-stopped")
	add-gdb-tail-args
}

compute-gdb-remote-args() {
	target_image=$1
	target_cx=$2
	rmi_address=$3

	args+=("$OPT_GDB_PATH")
	add-gdb-init-args
	add-gdb-image-and-args "$target_image"
	args+=(-ex "echo Connecting to $target_cx\n")
	args+=(-ex "target $target_cx")
	add-gdb-connect-and-sync "$rmi_address"
	args+=(-ex "ghidra trace sync-synth-stopped")
	add-gdb-tail-args
}

compute-gdb-pipinstall-args() {
	local argvpart
	printf -v argvpart ", %s" "$@"
	pipargs=("$OPT_GDB_PATH")
	pipargs+=(-q)
	pipargs+=(-ex "set pagination off")
	pipargs+=(-ex "python import os, sys, runpy")
	pipargs+=(-ex "python sys.argv=['pip', 'install', '--force-reinstall'$argvpart]")
	pipargs+=(-ex "python os.environ['PIP_BREAK_SYSTEM_PACKAGE']='1'")
	pipargs+=(-ex "python runpy.run_module('pip', run_name='__main__')")
}
