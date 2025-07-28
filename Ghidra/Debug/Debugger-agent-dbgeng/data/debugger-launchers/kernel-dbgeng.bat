::@title dbgeng kernel
::@desc <html><body width="300px">
::@desc   <h3>Kernel debugging using <tt>dbgeng</tt> (in a Python interpreter)</h3>
::@desc   <p>
::@desc     This will connect the kernel debugger to a remote machine using <tt>dbgeng.dll</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group dbgeng
::@icon icon.debugger
::@help dbgeng#win_kernel
::@depends Debugger-rmi-trace
::@enum Connection:str Remote Local EXDI
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
:: Use env instead of args, because "all args except first" is terrible to implement in batch
::@env OPT_KCONNECT_STRING:str="" "Arguments" "Connection-string arguments (a la .server)"
::@env OPT_TARGET_FLAGS:Connection="Remote" "Type" "Type/flags for connection (Remote/Local/EXDI)."
::@env OPT_USE_DBGMODEL:bool=true "Use dbgmodel" "Load and use dbgmodel.dll if it is available."
::@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."

@echo off

"%OPT_PYTHON_EXE%" -i ..\support\kernel-dbgeng.py
