::@title kernel lldb
::@desc <html><body width="300px">
::@desc   <h3>Launch with local <tt>lldb</tt> and connect to a remote kernel</h3>
::@desc   <p>
::@desc     This will start <tt>lldb</tt> on the local system and then use it to connect to the remote system.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group remote
::@icon icon.debugger
::@help lldb#macos_kernel
::@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
::@env OPT_ARCH:str="" "Architecture" "Target architecture override"
::@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."

@echo off
set PYTHONPATH0=%GHIDRA_HOME%\Ghidra\Debug\Debugger-agent-lldb\pypkg\src
set PYTHONPATH1=%GHIDRA_HOME%\Ghidra\Debug\Debugger-rmi-trace\pypkg\src
IF EXIST %GHIDRA_HOME%\.git (
  set PYTHONPATH0=%GHIDRA_HOME%\Ghidra\Debug\Debugger-agent-lldb\build\pypkg\src
  set PYTHONPATH1=%GHIDRA_HOME%\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src
)
IF EXIST %GHIDRA_HOME%\ghidra\.git (
  set PYTHONPATH0=%GHIDRA_HOME%\ghidra\Ghidra\Debug\Debugger-agent-lldb\build\pypkg\src
  set PYTHONPATH1=%GHIDRA_HOME%\ghidra\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src
)
set PYTHONPATH=%PYTHONPATH1%;%PYTHONPATH0%;%PYTHONPATH%

IF "%OPT_ARCH%"=="" (
	"%OPT_LLDB_PATH%" ^
	  -o "version" ^
	  -o "script import ghidralldb" ^
	  -o "kdp-remote %OPT_HOST%" ^
	  -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
	  -o "ghidra trace start" ^
	  -o "ghidra trace sync-enable" ^
	  -o "ghidra trace sync-synth-stopped"
) ELSE (
	"%OPT_LLDB_PATH%" ^
	  -o "version" ^
	  -o "script import ghidralldb" ^
	  -o "settings set target.default-arch %OPT_ARCH%"
	  -o "kdp-remote %OPT_HOST%" ^
	  -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
	  -o "ghidra trace start" ^
	  -o "ghidra trace sync-enable" ^
	  -o "ghidra trace sync-synth-stopped"
)