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
#@title wine + gdb
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt> and <tt>wine</tt></h3>
#@desc   <p>This will launch the target on the local machine using <tt>gdb</tt> and <tt>wine</tt>.
#@desc   GDB and Wine must already be installed on your system, and GDB must embed the Python 3
#@desc   interpreter. You will also need <tt>protobuf</tt> and <tt>psutil</tt> installed for Python
#@desc   3.</p>
#@desc   <p>This operates by starting GDB on the Wine executable and passing arguments to launch a
#@desc   Windows target. This may prevent GDB from processing the object file, because it is a PE
#@desc   file, and most copies of GDB for UNIX will support only ELF. Nevertheless, Ghidra should
#@desc   recognize the target and map it, giving you symbols and debug info in the front end, even
#@desc   if not in the GDB CLI.</p>
#@desc   <p>You will need to locate the <tt>wine</tt> executable, not the script, on your system. To
#@desc   find it, either dissect the <tt>wine</tt> script or consult online documentation for your
#@desc   distribution of Wine. There are often two executables, one for 32-bit targets and one for
#@desc   64-bit targets. You must select the correct one.</p>
#@desc </body></html>
#@menu-group cross
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb_wine
#@arg :str "Image" "The target binary executable image"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_WINE_PATH:str="/usr/lib/wine/wine64" "Path to wine binary" "The path to the wine executable for your target architecture."
#@env OPT_GDB_PATH:str="gdb" "Path to gdb" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_EXTRA_TTY:bool=false "Inferior TTY" "Provide a separate terminal emulator for the target."
#@tty TTY_TARGET if env:OPT_EXTRA_TTY

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

# NOTE: Ghidra will leave TTY_TARGET empty, which gdb takes for the same terminal.

"$OPT_GDB_PATH" \
  -q \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "show version" \
  -ex "python import ghidragdb.wine" \
  -ex "file \"$OPT_WINE_PATH\"" \
  -ex "set args $@" \
  -ex "set inferior-tty $TTY_TARGET" \
  -ex "starti" \
  -ex "ghidra wine run-to-image \"$1\"" \
  -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -ex "ghidra trace start \"$1\"" \
  -ex "ghidra trace sync-enable" \
  -ex "ghidra trace sync-synth-stopped" \
  -ex "set confirm on" \
  -ex "set pagination on"
