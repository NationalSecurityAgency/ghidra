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
::@title x64dbg attach
::@desc <html><body width="300px">
::@desc   <h3>Attach with <tt>x64dbg</tt> (in a Python interpreter)</h3>
::@desc   <p>
::@desc     This will attach to a running target on the local machine using <tt>x64dbg.dll</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group x64dbg
::@icon icon.debugger
::@help x64dbg#attach
::@depends Debugger-rmi-trace
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
::@env OPT_TARGET_PID:int=0 "Process id" "The target process id"
::@env OPT_X64DBG_EXE:file="C:\\Software\\release\\x64\\x64dbg.exe" "Path to x64dbg.exe" "Path to x64dbg.exe (or equivalent)."

@echo off

"%OPT_PYTHON_EXE%" -i ..\support\local-x64dbg-attach.py
