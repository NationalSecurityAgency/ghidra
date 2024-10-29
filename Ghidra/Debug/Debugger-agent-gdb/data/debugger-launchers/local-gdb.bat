::@title gdb
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>gdb</tt></h3>
::@desc   <p>
::@desc     This will launch the target on the local machine using <tt>gdb</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group local
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#gdb
::@enum StartCmd:str run start starti
::@env OPT_TARGET_IMG:file="" "Image" "The target binary executable image"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
::@env OPT_START_CMD:StartCmd="starti" "Run command" "The gdb command to actually run the target."

@echo off
set PYTHONPATH0=%GHIDRA_HOME%\Ghidra\Debug\Debugger-agent-gdb\pypkg\src
set PYTHONPATH1=%GHIDRA_HOME%\Ghidra\Debug\Debugger-rmi-trace\pypkg\src
IF EXIST %GHIDRA_HOME%\.git (
  set PYTHONPATH0=%GHIDRA_HOME%\Ghidra\Debug\Debugger-agent-gdb\build\pypkg\src
  set PYTHONPATH1=%GHIDRA_HOME%\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src
)
IF EXIST %GHIDRA_HOME%\ghidra\.git (
  set PYTHONPATH0=%GHIDRA_HOME%\ghidra\Ghidra\Debug\Debugger-agent-gdb\build\pypkg\src
  set PYTHONPATH1=%GHIDRA_HOME%\ghidra\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src
)
set PYTHONPATH=%PYTHONPATH1%;%PYTHONPATH0%;%PYTHONPATH%

"%OPT_GDB_PATH%" ^
  -q ^
  -ex "set pagination off" ^
  -ex "set confirm off" ^
  -ex "show version" ^
  -ex "python import ghidragdb" ^
  -ex "target exec %OPT_TARGET_IMG%" ^
  -ex "set args %OPT_TARGET_ARGS%" ^
  -ex "set inferior-tty %TTY_TARGET%" ^
  -ex "ghidra trace connect '%GHIDRA_TRACE_RMI_ADDR%'" ^
  -ex "ghidra trace start" ^
  -ex "ghidra trace sync-enable" ^
  -ex "%OPT_START_CMD%" ^
  -ex "set confirm on" ^
  -ex "set pagination on"
