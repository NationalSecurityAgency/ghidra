::@title dbgeng TTD
::@desc <html><body width="300px">
::@desc   <h3>Open trace with <tt>dbgeng</tt> (in a Python interpreter)</h3>
::@desc   <p>
::@desc     This will open a WinDbg TTD trace of the target on the local machine using <tt>dbgeng.dll</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group dbgeng
::@icon icon.debugger
::@help dbgeng#ttd
::@depends Debugger-rmi-trace
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
:: Use env instead of args, because "all args except first" is terrible to implement in batch
::@env OPT_TARGET_TRACE:file="" "Trace (.run)" "The target trace image"
::@env OPT_USE_DBGMODEL:bool=true "Use dbgmodel" "Load and use dbgmodel.dll if it is available."
::@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."

@echo off

set USE_TTD=true
"%OPT_PYTHON_EXE%" -i ..\support\local-dbgeng-trace.py
