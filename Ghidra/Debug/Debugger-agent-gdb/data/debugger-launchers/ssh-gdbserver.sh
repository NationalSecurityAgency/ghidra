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
#@title gdb + gdbserver via ssh
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and <tt>gdbserver</tt> via <tt>ssh</tt></h3>
#@desc   <p>This will start <tt>gdb</tt> on the local system and then use it to connect and launch
#@desc   the target in <tt>gdbserver</tt> on the remote system via <tt>ssh</tt>. The actual command
#@desc   used is, e.g:</p>
#@desc   <pre>target remote | ssh user@host gdbserver - /path/to/image</pre>
#@desc   <p>It may be worth testing this manually to ensure everything is configured correctly. An
#@desc   SSH server and <tt>gdbserver</tt> must already be installed and operational on the remote
#@desc   system. GDB must be installed on your local system, it must be compatible with the
#@desc   <tt>gdbserver</tt> on the remote system, and it must embed the Python 3 interpreter. You
#@desc   will also need <tt>protobuf</tt> installed for Python 3 on the local system. There are no
#@desc   Python requirements for the remote system.</p>
#@desc </body></html>
#@menu-group remote
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#gdb
#@arg :str "Image" "The target binary executable image on the remote system"
#@args "Arguments" "Command-line arguments to pass to the target"
#@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
#@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
#@env OPT_GDBSERVER_PATH:str="gdbserver" "Path to gdbserver (remote)" "The path to gdbserver on the remote system. Omit the full path to resolve using the system PATH."
#@env OPT_EXTRA_GDBSERVER_ARGS:str="" "Extra gdbserver arguments" "Extra arguments to pass to gdbserver. Use with care."
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

"$OPT_GDB_PATH" \
  -q \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "show version" \
  -ex "python import ghidragdb" \
  -ex "set inferior-tty $TTY_TARGET" \
  -ex "target remote | ssh $OPT_EXTRA_SSH_ARGS '$OPT_HOST' '$OPT_GDBSERVER_PATH' $OPT_EXTRA_GDBSERVER_ARGS - $@" \
  -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -ex "ghidra trace start" \
  -ex "ghidra trace sync-enable" \
  -ex "ghidra trace sync-synth-stopped" \
  -ex "set confirm on" \
  -ex "set pagination on"
