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
#@title qemu + gdb
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>qemu</tt> and connect with <tt>gdb</tt></h3>
#@desc   <p>This will launch the target on the local machine using <tt>qemu</tt>. Then in a second
#@desc   terminal, it will connect <tt>gdb</tt> to QEMU's GDBstub.
#@desc   GDB must already be installed on your system, it must support your target architecture
#@desc   (you may install <tt>gdb-multiarch</tt>), and it must embed the Python 3 interpreter. You
#@desc   will also need <tt>protobuf</tt> installed for Python 3.
#@desc </body></html>
#@menu-group cross
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb_qemu
#@arg :str "Image" "The target binary executable image"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env GHIDRA_LANG_EXTTOOL_qemu:str="" "Path to qemu" "The path to qemu for the target architecture."
#@env QEMU_GDB:int=12345 "QEMU Port" "Port for gdb connection to qemu"
#@env OPT_EXTRA_QEMU_ARGS:str="" "Extra qemu arguments" "Extra arguments to pass to qemu. Use with care."
#@env OPT_GDB_PATH:str="gdb-multiarch" "Path to gdb" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_EXTRA_TTY:bool=false "QEMU TTY" "Provide a separate terminal emulator for the target."
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

target_image="$1"

if [ -z "$TTY_TARGET" ]
then
  "$GHIDRA_LANG_EXTTOOL_qemu" $OPT_EXTRA_QEMU_ARGS $@ &
else
  "$GHIDRA_LANG_EXTTOOL_qemu" $OPT_EXTRA_QEMU_ARGS $@ <$TTY_TARGET >$TTY_TARGET 2>&1 &
fi

# Give QEMU a moment to open the socket
sleep 0.1

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
  -ex "target remote localhost:$QEMU_GDB" \
  -ex "set confirm on" \
  -ex "set pagination on"
