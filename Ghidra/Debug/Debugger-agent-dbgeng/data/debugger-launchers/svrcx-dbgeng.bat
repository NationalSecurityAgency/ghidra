::@title dbgeng svrcx
::@image-opt env:OPT_TARGET_IMG
::@desc <html><body width="300px">
::@desc   <h3>Connect to a remote <tt>dbgeng</tt> connection server and launch the target (in a Python interpreter)</h3>
::@desc   <p>
::@desc     This will launch the target via a connection server on a remote machine.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group dbgeng
::@icon icon.debugger
::@help dbgeng#svrcx
::@depends Debugger-rmi-trace
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
:: Use env instead of args, because "all args except first" is terrible to implement in batch
::@env OPT_TARGET_IMG:str="" "Image" "The target binary executable image"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_CONNECT_STRING:str="" "Connection" "Connection-string arguments (a la dbgsrv args)"
::@env OPT_USE_DBGMODEL:bool=true "Use dbgmodel" "Load and use dbgmodel.dll if it is available."
::@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."

@echo off

"%OPT_PYTHON_EXE%" -i ..\support\svrcx-dbgeng.py
