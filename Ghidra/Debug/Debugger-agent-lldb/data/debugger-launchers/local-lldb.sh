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
#@title lldb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>lldb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>lldb</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group lldb
#@icon icon.debugger
#@help lldb#local
#@depends Debugger-rmi-trace
#@enum StartCmd:str "process launch" "process launch --stop-at-entry"
#@arg :file "Image" "The target binary executable image"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."
#@env OPT_EXTRA_TTY:bool=false "Target TTY" "Provide a separate terminal emulator for the target."
#@tty TTY_TARGET if env:OPT_EXTRA_TTY

. ../support/lldbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathLldb=$(ghidra-module-pypath)
export PYTHONPATH=$pypathLldb:$pypathTrace:$PYTHONPATH

target_image="$1"
shift

function launch-lldb() {
	local -a args
	compute-lldb-usermode-args "$target_image" "$GHIDRA_TRACE_RMI_ADDR" "$@"

	"${args[@]}"
}
launch-lldb "$@"
