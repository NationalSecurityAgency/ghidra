#!/usr/bin/env bash
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
#@title gdb-rr
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>rr/gdb</tt></h3>
#@desc   <p>
#@desc     This will open a trace of a target on the local machine using <tt>rr/gdb</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#rr
#@depends Debugger-rmi-trace
#@enum StartCmd:str run start starti
#@enum Endian:str auto big little
#@arg :file "Trace Dir" "The target trace directory (e.g. .local/share/rr/trace)"
#@env OPT_RR_PATH:file="rr" "rr command" "The path to rr. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"
#@env OPT_EXTRA_TTY:bool=false "Inferior TTY" "Provide a separate terminal emulator for the target."
#@tty TTY_TARGET if env:OPT_EXTRA_TTY

. ../support/gdbsetuputils.sh

pypathTrace=$(ghidra-module-pypath "Debugger-rmi-trace")
pypathGdb=$(ghidra-module-pypath)
export PYTHONPATH=$pypathGdb:$pypathTrace:$PYTHONPATH

target_trace="$1"

# Ghidra will leave TTY_TARGET empty when OPT_EXTRA_TTY is false. Gdb takes empty to mean the same terminal.

RRINIT=$(mktemp)
echo '
set pagination off
set confirm off
set $use_trace="true"
show version
python import ghidragdb
set architecture ' $OPT_ARCH '
set endian ' $OPT_ENDIAN '
set inferior-tty ' $TTY_TARGET '
ghidra trace connect ' $GHIDRA_TRACE_RMI_ADDR '
ghidra trace start
ghidra trace sync-enable 
set confirm on
set pagination on
' > $RRINIT

"$OPT_RR_PATH" replay -x $RRINIT "$target_trace"

