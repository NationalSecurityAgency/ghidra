#!/usr/bin/bash
## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
#@timeout 60000
#@title gdb via ssh
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt> via <tt>ssh</tt></h3>
#@desc   <p>This will launch the target on a remote machine using <tt>gdb</tt> via <tt>ssh</tt>.
#@desc   GDB and an SSH server must already be installed and operational on the remote system, and
#@desc   GDB must embed the Python 3 interpreter. The remote SSH server must be configured to allow
#@desc   remote port forwarding. You will also need to install the following for GDB's embedded
#@desc   version of Python:</p>
#@desc   <ul>
#@desc     <li><tt>ghidragdb</tt> - Ghidra plugin for GDB, available from the Debugger-agent-gdb
#@desc         directory in Ghidra</li>
#@desc     <li><tt>ghidratrace</tt> - Ghidra Trace RMI client for Python, available from the
#@desc         Debugger-rmi-trace directory in Ghidra</li>
#@desc     <li><tt>protobuf</tt> - available from PyPI</li>
#@desc     <li><tt>psutil</tt> - available from PyPI</li>
#@desc   </ul>
#@desc </body></html>
#@menu-group remote
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb_ssh
#@enum StartCmd:str run start starti
#@arg :str "Image" "The target binary executable image on the remote system"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
#@env OPT_REMOTE_PORT:int=12345 "Remote Trace RMI Port" "A free port on the remote end to receive and forward the Trace RMI connection."
#@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
#@env OPT_GDB_PATH:str="gdb" "Path to gdb" "The path to gdb on the remote system. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="start" "Run command" "The gdb command to actually run the target."

target_image="$1"
shift
target_args="$@"

ssh "-R$OPT_REMOTE_PORT:$GHIDRA_TRACE_RMI_ADDR" -t $OPT_EXTRA_SSH_ARGS "$OPT_HOST" "TERM='$TERM' '$OPT_GDB_PATH' \
  -q \
  -ex 'set pagination off' \
  -ex 'set confirm off' \
  -ex 'show version' \
  -ex 'python import ghidragdb' \
  -ex 'file \"$target_image\"' \
  -ex 'set args $target_args' \
  -ex 'ghidra trace connect \"localhost:$OPT_REMOTE_PORT\"' \
  -ex 'ghidra trace start' \
  -ex 'ghidra trace sync-enable' \
  -ex '$OPT_START_CMD' \
  -ex 'set confirm on' \
  -ex 'set pagination on'"
