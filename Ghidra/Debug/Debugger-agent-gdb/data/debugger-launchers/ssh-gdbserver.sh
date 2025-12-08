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
#@title gdb + gdbserver via ssh
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and <tt>gdbserver</tt> via <tt>ssh</tt></h3>
#@desc   <p>
#@desc     This will start <tt>gdb</tt> on the local system and then use it to connect and launch the target in <tt>gdbserver</tt> on the remote system via <tt>ssh</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#gdbserver_ssh
#@depends Debugger-rmi-trace
#@enum Endian:str auto big little
#@arg :str! "Image" "The target binary executable image on the remote system"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_SSH_PATH:file!="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
#@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
#@env OPT_GDBSERVER_PATH:str="gdbserver" "gdbserver command (remote)" "The path to gdbserver on the remote system. Omit the full path to resolve using the system PATH."
#@env OPT_EXTRA_GDBSERVER_ARGS:str="" "Extra gdbserver arguments" "Extra arguments to pass to gdbserver. Use with care."
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

. ../support/gdbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathGdb=$(ghidra-module-pypath)
export PYTHONPATH=$pypathGdb:$pypathTrace:$PYTHONPATH

target_image="$1"
shift

function launch-gdb() {
	local qargs
	printf -v qargs '%q ' "$@"
	local -a args
	compute-gdb-remote-args "$target_image" "remote | '$OPT_SSH_PATH' $OPT_EXTRA_SSH_ARGS '$OPT_HOST' '$OPT_GDBSERVER_PATH' $OPT_EXTRA_GDBSERVER_ARGS - '$target_image' $qargs" "$GHIDRA_TRACE_RMI_ADDR"

	"${args[@]}"
}
launch-gdb "$@"
