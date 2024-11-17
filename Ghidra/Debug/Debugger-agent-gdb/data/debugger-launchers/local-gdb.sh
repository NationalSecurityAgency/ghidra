#!/usr/bin/bash
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
#@title gdb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>gdb</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group local
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb
#@enum StartCmd:str run start starti
#@arg :file "Image" "The target binary executable image, empty for no target"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="starti" "Run command" "The gdb command to actually run the target."
#@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"
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

target_image="$1"
shift
target_args="$@"

# Ghidra will leave TTY_TARGET empty when OPT_EXTRA_TTY is false. Gdb takes empty to mean the same terminal.

if [ -z "$target_image" ]
then
  "$OPT_GDB_PATH" \
    -q \
    -ex "set pagination off" \
    -ex "set confirm off" \
    -ex "show version" \
    -ex "python import ghidragdb" \
    -ex "set architecture $OPT_ARCH" \
    -ex "set inferior-tty $TTY_TARGET" \
    -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
    -ex "ghidra trace start" \
    -ex "ghidra trace sync-enable" \
    -ex "set confirm on" \
    -ex "set pagination on"
else
  "$OPT_GDB_PATH" \
    -q \
    -ex "set pagination off" \
    -ex "set confirm off" \
    -ex "show version" \
    -ex "python import ghidragdb" \
    -ex "set architecture $OPT_ARCH" \
    -ex "file \"$target_image\"" \
    -ex "set args $target_args" \
    -ex "set inferior-tty $TTY_TARGET" \
    -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
    -ex "ghidra trace start" \
    -ex "ghidra trace sync-enable" \
    -ex "$OPT_START_CMD" \
    -ex "set confirm on" \
    -ex "set pagination on"
fi
