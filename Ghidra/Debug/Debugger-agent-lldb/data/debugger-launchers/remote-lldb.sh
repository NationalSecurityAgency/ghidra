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
#@title remote lldb
#@no-image
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>lldb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>This will start <tt>lldb</tt> on the local system and then use it to connect to the remote system. 
#@desc   The actual command used is, e.g:</p>
#@desc   <pre>gdb-remote host:port</pre>
#@desc   <p>It may be worth testing this manually to ensure everything is configured correctly.
#@desc   LLDB must be installed on your local system, it must be compatible with the remote system, 
#@desc   and it must embed the Python 3 interpreter. You will also need <tt>protobuf</tt> installed 
#@desc   for Python 3 on the local system. There are no Python requirements for the remote system.
#@desc   Please ensure that Ghidra's current program and the target's image match.  Otherwise, the
#@desc   modules may not map.</p>
#@desc </body></html>
#@menu-group remote
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#lldb_remote
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:str="9999" "Port" "The host's listening port"
#@env OPT_ARCH:str="" "Architecture" "Target architecture override"
#@env OPT_LLDB_PATH:str="lldb" "Path to lldb" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."

if [ -d ${GHIDRA_HOME}/ghidra/.git ]
then
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-agent-lldb/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
elif [ -d ${GHIDRA_HOME}/.git ]
then 
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-lldb/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
else
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-lldb/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/pypkg/src:$PYTHONPATH
fi

if [ -z "$OPT_ARCH" ]
then
  archcmd=
else
  archcmd=-o "settings set target.default-arch $OPT_ARCH" 
fi

"$OPT_LLDB_PATH" \
  -o "version" \
  -o "script import ghidralldb" \
  $archcmd \
  -o "gdb-remote $OPT_HOST:$OPT_PORT" \
  -o "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -o "ghidra trace start" \
  -o "ghidra trace sync-enable" \
  -o "ghidra trace sync-synth-stopped" 
  
