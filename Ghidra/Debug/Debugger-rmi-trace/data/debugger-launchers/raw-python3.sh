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

#@title raw python
#@desc <html><body width="300px">
#@desc   <h3>Start <tt>gdb</tt></h3>
#@desc   <p>
#@desc     This will start <tt>python</tt>, import <tt>ghidratrace</tt> and connect to it for development purposes.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group raw
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#python_raw
#@env OPT_PYTHON_EXE:file="python" "python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
#@env OPT_LANG:str="DATA:LE:64:default" "Ghidra Language" "The Ghidra LanguageID for the trace"
#@env OPT_COMP:str="pointer64" "Ghidra Compiler" "The Ghidra CompilerSpecID for the trace"

. ../support/setuputils.sh

pypathTrace=$(ghidra-module-pypath)
export PYTHONPATH=$pypathTrace:$PYTHONPATH

"$OPT_PYTHON_EXE" -i ../support/raw-python3.py
