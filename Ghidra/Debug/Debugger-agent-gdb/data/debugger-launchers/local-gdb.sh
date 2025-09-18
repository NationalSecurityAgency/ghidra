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
#@title gdb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>gdb</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#local
#@depends Debugger-rmi-trace
#@enum StartCmd:str run start starti
#@enum Endian:str auto big little
#@arg :file "Image" "The target binary executable image, empty for no target"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="starti" "Run command" "The gdb command to actually run the target."
#@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"
#@env OPT_EXTRA_TTY:bool=false "Inferior TTY" "Provide a separate terminal emulator for the target."
#@tty TTY_TARGET if env:OPT_EXTRA_TTY

. ../support/gdbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathGdb=$(ghidra-module-pypath)
export PYTHONPATH=$pypathGdb:$pypathTrace:$PYTHONPATH

target_image="$1"
shift

function launch-gdb() {
	local -a args
	compute-gdb-usermode-args "$target_image" "$GHIDRA_TRACE_RMI_ADDR" "$@"

	"${args[@]}"
}
launch-gdb "$@"
