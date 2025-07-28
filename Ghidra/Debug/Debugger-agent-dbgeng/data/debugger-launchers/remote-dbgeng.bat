::@title dbgeng remote
::@desc <html><body width="300px">
::@desc   <h3>Connect to a remote debugger (via the .server interface)</h3>
::@desc   <p>
::@desc     This will connect to a remote machine using the .server interface.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group dbgeng
::@icon icon.debugger
::@help dbgeng#remote
::@depends Debugger-rmi-trace
::@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
::@env OPT_CONNECT_STRING:str="" "Connection" "Connection-string arguments (a la .server)"
::@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."

@echo off

"%OPT_PYTHON_EXE%" -i ..\support\remote-dbgeng.py
