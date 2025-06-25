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
#@title lldb Android
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>lldb</tt> and connect to an Android target.</h3>
#@desc   <p>
#@desc     This will start <tt>lldb</tt> on the local system and then use it to connect to the remote system.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group lldb
#@icon icon.debugger
#@help lldb#android
#@enum StartCmd:str "process launch" "process launch --stop-at-entry"
#@arg :file "Image" "The target binary executable image"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:str="9999" "Port" "The host's listening port"
#@env OPT_ARCH:str="" "Architecture" "Target architecture override"
#@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."

. ../support/lldbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debug/Debugger-rmi-trace")
pypathLldb=$(ghidra-module-pypath "Debug/Debugger-agent-lldb")
export PYTHONPATH=$pypathLldb:$pypathTrace:$PYTHONPATH

target_image="$1"
shift
target_args="$@"

function launch-lldb() {
	local -a args
	compute-lldb-platform-args "$target_image" remote-android "connect://$OPT_HOST:$OPT_PORT" "$GHIDRA_TRACE_RMI_ADDR" "$@"

	"${args[@]}"
}
launch-lldb "$@"
