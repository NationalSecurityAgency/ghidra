:: ###
:: IP: GHIDRA
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
:: ##
::@title dbgeng attach
::@desc <html><body width="300px">
::@desc   <h3>Attach with <tt>dbgeng</tt> (in a Python interpreter)</h3>
::@desc   <p>
::@desc     This will attach to a running target on the local machine using <tt>dbgeng.dll</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group dbgeng
::@icon icon.debugger
::@help dbgeng#attach
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
::@env OPT_TARGET_PID:int=0 "Process id" "The target process id"
::@env OPT_ATTACH_FLAGS:int=0 "Attach flags" "Attach flags"
::@env OPT_USE_DBGMODEL:bool=true "Use dbgmodel" "Load and use dbgmodel.dll if it is available."
::@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."

@echo off

"%OPT_PYTHON_EXE%" -i ..\support\local-dbgeng-attach.py
