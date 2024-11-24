::@title remote gdb
::@desc <html><body width="300px">
::@desc   <h3>Launch with local <tt>gdb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
::@desc   <p>
::@desc     This will start <tt>gdb</tt> on the local system and then use it to connect to the remote system. 
::@desc     For setup instructions, press <b>F1</b>. 
::@desc   </p>
::@desc </body></html>
::@menu-group remote
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#gdb_remote
::@enum TargetType:str remote extended-remote
::@env OPT_TARGET_TYPE:TargetType="remote" "Target" "The type of remote target"
::@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
::@env OPT_PORT:int=9999 "Port" "The host's listening port"
::@env OPT_ARCH:str="auto" "Architecture" "Target architecture override"
::@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."

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
  -ex "set arch %OPT_ARCH%" ^
  -ex "echo Connecting to %OPT_HOST%:%OPT_PORT%... " ^
  -ex "target %OPT_TARGET_TYPE% %OPT_HOST%:%OPT_PORT%" ^
  -ex "ghidra trace connect '%GHIDRA_TRACE_RMI_ADDR%'" ^
  -ex "ghidra trace start" ^
  -ex "ghidra trace sync-enable" ^
  -ex "ghidra trace sync-synth-stopped" ^
  -ex "set confirm on" ^
  -ex "set pagination on"
