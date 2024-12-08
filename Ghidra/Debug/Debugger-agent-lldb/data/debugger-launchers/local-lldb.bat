::@title lldb
::@image-opt arg:1
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>lldb</tt></h3>
::@desc   <p>
::@desc     This will launch the target on the local machine using <tt>lldb</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group local
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#lldb
::@enum StartCmd:str "process launch" "process launch --stop-at-entry"
::@arg :file "Image" "The target binary executable image"
::@args "Arguments" "Command-line arguments to pass to the target"
::@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb. Omit the full path to resolve using the system PATH."
::@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."

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

set target_image=%1
shift
set target_args=%*

IF DEFINED target_args (
  argspart=-o "settings set target.run-args %target_args%"
)

IF "%target_image%"=="" (
  "%OPT_LLDB_PATH%" ^
    -o "version" ^
    -o "script import ghidralldb" ^
    -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
    -o "ghidra trace start" ^
    -o "ghidra trace sync-enable" ^
) ELSE (
  "%OPT_LLDB_PATH%" ^
    -o "version" ^
    -o "script import ghidralldb" ^
    -o "target create %target_image%" ^
    %argspart% ^
    -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
    -o "ghidra trace start" ^
    -o "ghidra trace sync-enable" ^
    -o "%OPT_START_CMD%"
)
