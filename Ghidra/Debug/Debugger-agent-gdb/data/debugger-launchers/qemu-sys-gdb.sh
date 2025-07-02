#!/usr/bin/env bash
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
#@title gdb + qemu-system
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>qemu-system</tt> and connect with <tt>gdb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>qemu-system</tt>.
#@desc     Then in a second terminal, it will connect <tt>gdb</tt> to QEMU's GDBstub.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#qemu
#@depends Debugger-rmi-trace
#@enum Endian:str auto big little
#@arg :file! "Image" "The target binary executable image"
#@env GHIDRA_LANG_EXTTOOL_qemu_system:file="" "QEMU command" "The path to qemu-system for the target architecture."
#@env QEMU_GDB:int=1234 "QEMU Port" "Port for gdb connection to qemu"
#@env OPT_EXTRA_QEMU_ARGS:str="" "Extra qemu arguments" "Extra arguments to pass to qemu. Use with care."
#@env OPT_GDB_PATH:file="gdb-multiarch" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"
#@env OPT_EXTRA_TTY:bool=false "QEMU TTY" "Provide a separate terminal emulator for qemu."
#@env OPT_PULL_ALL_SECTIONS:bool=false "Pull all section mappings" "Force gdb to send all mappings to Ghidra. This can be costly (see help)."
#@tty TTY_TARGET if env:OPT_EXTRA_TTY

. ../support/gdbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathGdb=$(ghidra-module-pypath)
export PYTHONPATH=$pypathGdb:$pypathTrace:$PYTHONPATH

target_image="$1"

if [ -z "$TTY_TARGET" ]
then
	"$GHIDRA_LANG_EXTTOOL_qemu_system" $OPT_EXTRA_QEMU_ARGS -gdb tcp::$QEMU_GDB -S $target_image &
else
	"$GHIDRA_LANG_EXTTOOL_qemu_system" $OPT_EXTRA_QEMU_ARGS -gdb tcp::$QEMU_GDB -S $target_image <$TTY_TARGET >$TTY_TARGET 2>&1 &
fi

# Give QEMU a moment to open the socket
sleep 0.1

function launch-gdb() {
	local -a args
	compute-gdb-remote-args "$target_image" "remote localhost:$QEMU_GDB" "$GHIDRA_TRACE_RMI_ADDR"

	if [ "$OPT_PULL_ALL_SECTIONS" = "true" ]; then
		args+=(-ex "ghidra trace tx-open 'Put Sections' 'ghidra trace put-sections -all-objects'")
	fi

	"${args[@]}"
}
launch-gdb
