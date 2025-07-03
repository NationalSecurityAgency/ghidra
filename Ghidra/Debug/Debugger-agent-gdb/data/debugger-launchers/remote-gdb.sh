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
#@title gdb remote
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>
#@desc     This will start <tt>gdb</tt> on the local system and then use it to connect to the remote system. 
#@desc     For setup instructions, press <b>F1</b>. 
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#remote
#@depends Debugger-rmi-trace
#@enum TargetType:str remote extended-remote
#@enum Endian:str auto big little
#@arg :file "Image" "The target binary executable image (a copy on the local system)"
#@env OPT_TARGET_TYPE:TargetType="remote" "Target" "The type of remote target"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:int=9999 "Port" "The host's listening port"
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture override"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

. ../support/gdbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathGdb=$(ghidra-module-pypath)
export PYTHONPATH=$pypathGdb:$pypathTrace:$PYTHONPATH

target_image="$1"

function launch-gdb() {
	local -a args
	compute-gdb-remote-args "$target_image" "$OPT_TARGET_TYPE $OPT_HOST:$OPT_PORT" "$GHIDRA_TRACE_RMI_ADDR"

	"${args[@]}"
}
launch-gdb
