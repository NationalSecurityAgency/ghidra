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
#@title raw gdb
#@no-image
#@desc <html><body width="300px">
#@desc   <h3>Start <tt>gdb</tt></h3>
#@desc   <p>This will start <tt>gdb</tt> and connect to it. It will not launch
#@desc   a target, so you can (must) set up your target manually.
#@desc   GDB must already
#@desc   be installed on your system, and it must embed the Python 3 interpreter. You will also
#@desc   need <tt>protobuf</tt> and <tt>psutil</tt> installed for Python 3.</p>
#@desc </body></html>
#@menu-group raw
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb_raw
#@env OPT_GDB_PATH:str="gdb" "Path to gdb" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"

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

"$OPT_GDB_PATH" \
  -q \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "show version" \
  -ex "python import ghidragdb" \
  -ex "set architecture $OPT_ARCH" \
  -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -ex "ghidra trace start" \
  -ex "ghidra trace sync-enable" \
  -ex "set confirm on" \
  -ex "set pagination on"
