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
#@title gdb
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt></h3>
#@desc   <p>This will launch the target on the local machine using <tt>gdb</tt>. GDB must already
#@desc   be installed on your system, and it must embed the Python 3 interpreter. You will also
#@desc   need <tt>protobuf</tt> and <tt>psutil</tt> installed for Python 3.
#@desc </body></html>
#@menu-group local
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb
#@enum StartCmd:str run start starti
#@env OPT_GDB_PATH:str="gdb" "Path to gdb" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="start" "Run command" "The gdb command to actually run the target."
#@arg :str "Image" "The target binary executable image"
#@args "Arguments" "Command-line arguments to pass to the target"
#@tty TTY_TARGET

if [ -d ${GHIDRA_HOME}/ghidra/.git ]
then
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-agent-gdb/build/pypkg/src:$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
elif [ -d ${GHIDRA_HOME}/.git ]
then 
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-gdb/build/pypkg/src:$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
else
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-gdb/pypkg/src:$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
fi

target_image="$1"
shift
target_args="$@"

"$OPT_GDB_PATH" \
  -q \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "show version" \
  -ex "python import ghidragdb" \
  -ex "file \"$target_image\"" \
  -ex "set args $target_args" \
  -ex "set inferior-tty $TTY_TARGET" \
  -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -ex "ghidra trace start" \
  -ex "ghidra trace sync-enable" \
  -ex "$OPT_START_CMD" \
  -ex "set confirm on" \
  -ex "set pagination on"
