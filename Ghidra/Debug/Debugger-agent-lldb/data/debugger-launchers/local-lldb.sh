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
#@title lldb
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>lldb</tt></h3>
#@desc   <p>This will launch the target on the local machine using <tt>lldb</tt>. LLDB must already
#@desc   be installed on your system, and it must embed the Python 3 interpreter. You will also
#@desc   need <tt>protobuf</tt> and <tt>psutil</tt> installed for Python 3.</p>
#@desc </body></html>
#@menu-group local
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#lldb
#@enum StartCmd:str "process launch" "process launch --stop-at-entry"
#@arg :str "Image" "The target binary executable image"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_LLDB_PATH:str="lldb" "Path to lldb" "The path to lldb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."
#@env OPT_EXTRA_TTY:bool=false "Target TTY" "Provide a separate terminal emulator for the target."
#@tty TTY_TARGET if env:OPT_EXTRA_TTY

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

target_image="$1"
shift
target_args="$@"

if [ -z "$target_args" ]
then
  argspart=
else
  argspart=-o "settings set target.run-args $target_args"
fi

if [ -z "$TARGET_TTY" ]
then
  ttypart=
else
  ttypart=-o "settings set target.output-path $TTY_TARGET" -o "settings set target.input-path $TTY_TARGET"
fi

"$OPT_LLDB_PATH" \
  -o "version" \
  -o "script import ghidralldb" \
  -o "target create \"$target_image\"" \
  $argspart \
  $ttypart \
  -o "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -o "ghidra trace start" \
  -o "ghidra trace sync-enable" \
  -o "$OPT_START_CMD"
