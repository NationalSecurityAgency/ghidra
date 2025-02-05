::@title dbgeng-ext
::@image-opt env:OPT_TARGET_IMG
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>dbgeng</tt> (in a Python interpreter)</h3>
::@desc   <p>
::@desc     This will launch the target on the local machine using <tt>dbgeng.dll</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group local
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#dbgeng_ext
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
:: Use env instead of args, because "all args except first" is terrible to implement in batch
::@env OPT_TARGET_IMG:file!="" "Image" "The target binary executable image"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_USE_DBGMODEL:bool=true "Use dbgmodel" "Load and use dbgmodel.dll if it is available."
::@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."
::@env OPT_TARGET_DIR:str="" "Dir" "Initial directory"
::@env OPT_TARGET_ENV:str="" "Env" "Environment variables (sep=/0)"
::@env OPT_CREATE_FLAGS:int="1" "Create flags" "Creation flags"
::@env OPT_CREATE_ENGFLAGS:int="0" "Create flags (Engine)" "Engine-specific creation flags"
::@env OPT_VERIFIER_FLAGS:int="0" "Verifier flags" "Verifier flags"

@echo off

"%OPT_PYTHON_EXE%" -i ..\support\local-dbgeng-ext.py
