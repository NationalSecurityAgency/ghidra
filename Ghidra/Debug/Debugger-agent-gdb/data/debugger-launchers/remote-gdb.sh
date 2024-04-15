#!/usr/bin/env bash
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
#@title remote gdb
#@no-image
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>This will start <tt>gdb</tt> on the local system and then use it to connect to the remote system. 
#@desc   The actual command used is, e.g:</p>
#@desc   <pre>target remote host:port</pre>
#@desc   <p>It may be worth testing this manually to ensure everything is configured correctly.
#@desc   GDB must be installed on your local system, it must be compatible with the remote system, 
#@desc   and it must embed the Python 3 interpreter. You will also need <tt>protobuf</tt> installed 
#@desc   for Python 3 on the local system. There are no Python requirements for the remote system.
#@desc   Please ensure that Ghidra's current program and the target's image match.  Otherwise, the
#@desc   modules may not map.</p>
#@desc </body></html>
#@menu-group remote
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb
#@enum TargetType:str remote extended-remote
#@env OPT_TARGET_TYPE:TargetType="remote" "Target" "The type of remote target"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:str="9999" "Port" "The host's listening port"
#@env OPT_ARCH:str="" "Architecture (optional)" "Target architecture override"
#@env OPT_GDB_PATH:str="gdb" "Path to gdb" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."

if [ -d ${GHIDRA_HOME}/ghidra/.git ]
then
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-agent-gdb/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
elif [ -d ${GHIDRA_HOME}/.git ]
then 
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-gdb/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
else
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-gdb/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/pypkg/src:$PYTHONPATH
fi

if [ -z "$OPT_ARCH" ]
then
  archcmd=
else
  archcmd=-ex "set arch $OPT_ARCH" 
fi

"$OPT_GDB_PATH" \
  -q \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "show version" \
  -ex "python import ghidragdb" \
  $archcmd \
  -ex "target $OPT_TARGET_TYPE $OPT_HOST:$OPT_PORT" \
  -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -ex "ghidra trace start" \
  -ex "ghidra trace sync-enable" \
  -ex "ghidra trace sync-synth-stopped" \
  -ex "set confirm on" \
  -ex "set pagination on"
