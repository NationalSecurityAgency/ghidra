::@title raw gdb
::@no-image
::@desc <html><body width="300px">
::@desc   <h3>Start <tt>gdb</tt></h3>
::@desc   <p>
::@desc     This will start <tt>gdb</tt> and connect to it.
::@desc     It will not launch a target, so you can (must) set up your target manually.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group raw
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#gdb_raw
::@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
::@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"

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
  -ex "set architecture %OPT_ARCH%" ^
  -ex "ghidra trace connect '%GHIDRA_TRACE_RMI_ADDR%'" ^
  -ex "ghidra trace start" ^
  -ex "ghidra trace sync-enable" ^
  -ex "set confirm on" ^
  -ex "set pagination on"
