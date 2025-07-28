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

add-lldb-init-args() {
	args+=(-o "version")
	args+=(-o "script import os, ghidralldb")
	args+=(-o "script if not 'ghidralldb' in locals(): os._exit(253)")

	if [ -n "$OPT_ARCH" ]; then
		args+=(-o "settings set target.default-arch $OPT_ARCH")
	fi
}

add-lldb-image-and-args() {
	target_image=$1
	shift

	if [ -n "$target_image" ]; then
		if [ -n "$OPT_ARCH" ]; then
			args+=(-o "target create --arch '$OPT_ARCH' '$target_image'")
		else
			args+=(-o "target create '$target_image'")
		fi
	fi
	if [ "$#" -ne 0 ]; then
		local qargs
		printf -v qargs '%q ' "$@"
		args+=(-o "settings set -- target.run-args $qargs")
	fi
}

add-lldb-io-tty() {
	if [ -n "$TTY_TARGET" ]; then
		args+=(-o "settings set target.output-path '$TTY_TARGET'")
		args+=(-o "settings set target.input-path '$TTY_TARGET'")
	fi
}

add-lldb-connect-and-sync() {
	address=$1

	args+=(-o "ghidra trace connect '$address'")
	args+=(-o "ghidra trace start")
	args+=(-o "ghidra trace sync-enable")
}

add-lldb-start-if-image() {
	target_image=$1

	if [ -n "$target_image" ]; then
		args+=(-o "$OPT_START_CMD")
	fi
}

add-lldb-tail-args() {
	true
}

compute-lldb-usermode-args() {
	target_image=$1
	rmi_address=$2
	shift
	shift

	args+=("$OPT_LLDB_PATH")
	add-lldb-init-args
	add-lldb-image-and-args "$target_image" "$@"
	add-lldb-io-tty
	add-lldb-connect-and-sync "$rmi_address"
	add-lldb-start-if-image "$target_image"
	add-lldb-tail-args
}

compute-lldb-platform-args() {
	target_image=$1
	target_type=$2
	target_url=$3
	rmi_address=$4
	shift
	shift
	shift
	shift

	args+=("$OPT_LLDB_PATH")
	add-lldb-init-args
	args+=(-o "platform select '$target_type'")
	args+=(-o "platform connect '$target_url'")
	add-lldb-image-and-args "$target_image" "$@"
	add-lldb-connect-and-sync "$rmi_address"
	add-lldb-start-if-image "$target_image"
	add-lldb-tail-args
}

compute-lldb-remote-args() {
	target_image=$1
	target_cx=$2
	rmi_address=$3

	args+=("$OPT_LLDB_PATH")
	add-lldb-init-args
	add-lldb-image-and-args "$target_image" ""
	args+=(-o "$target_cx")
	add-lldb-connect-and-sync "$rmi_address"
	args+=(-o "ghidra trace sync-synth-stopped")
	add-lldb-tail-args
}

compute-lldb-pipinstall-args() {
	local argvpart
	printf -v argvpart ", %s" "$@"
	pipargs=("$OPT_LLDB_PATH")
	pipargs+=(-o "script import os, sys, runpy")
	pipargs+=(-o "script sys.argv=['pip', 'install', '--force-reinstall'$argvpart]")
	pipargs+=(-o "script os.environ['PIP_BREAK_SYSTEM_PACKAGE']='1'")
	pipargs+=(-o "script runpy.run_module('pip', run_name='__main__')")
	pipargs+=(-o "quit")
}
