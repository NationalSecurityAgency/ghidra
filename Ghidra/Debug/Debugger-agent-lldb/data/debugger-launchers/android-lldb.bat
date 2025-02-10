::@title android lldb
::@desc <html><body width="300px">
::@desc   <h3>Launch with local <tt>lldb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
::@desc   <p>
::@desc     This will start <tt>lldb</tt> on the local system and then use it to connect to the remote system.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group remote
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#lldb_android
::@enum StartCmd:str "process launch" "process launch --stop-at-entry"
::@env OPT_TARGET_IMG:file="" "Image" "The target binary executable image"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
::@env OPT_PORT:str="9999" "Port" "The host's listening port"
::@env OPT_ARCH:str="" "Architecture" "Target architecture override"
::@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."
::@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."

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

:: NB: This works - a lot of things do not. Don't change unless you know what you're doing!
set OPT_TARGET_IMG="%OPT_TARGET_IMG%"
set OPT_TARGET_ARGS="%OPT_TARGET_ARGS%"

IF %OPT_ARCH%=="" (
	IF "%OPT_TARGET_ARGS%"=="" (
	    "%OPT_LLDB_PATH%" ^
		  -o "version" ^
		  -o "script import ghidralldb" ^
		  -o "platform select remote-android" ^
		  -o "platform connect connect://%OPT_HOST%:%OPT_PORT%" ^
	      -o "target create "%OPT_TARGET_IMG%"" ^
		  -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
		  -o "ghidra trace start" ^
		  -o "ghidra trace sync-enable" ^
		  -o "ghidra trace sync-synth-stopped" ^
	      -o "%OPT_START_CMD%"
	) ELSE (
	    "%OPT_LLDB_PATH%" ^
		  -o "version" ^
		  -o "script import ghidralldb" ^
		  -o "platform select remote-android" ^
		  -o "platform connect connect://%OPT_HOST%:%OPT_PORT%" ^
		  -o "settings set target.default-arch %OPT_ARCH%"
	      -o "target create "%OPT_TARGET_IMG%"" ^
		  -o "settings set target.run-args %OPT_TARGET_ARGS%" ^
		  -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
		  -o "ghidra trace start" ^
		  -o "ghidra trace sync-enable" ^
		  -o "ghidra trace sync-synth-stopped" ^
	      -o "%OPT_START_CMD%"
	)
) ELSE (
	if %OPT_TARGET_ARGS=="" (
	    "%OPT_LLDB_PATH%" ^
		  -o "version" ^
		  -o "script import ghidralldb" ^
		  -o "platform select remote-android" ^
		  -o "platform connect connect://%OPT_HOST%:%OPT_PORT%" ^
		  -o "settings set target.default-arch %OPT_ARCH%"
	      -o "target create "%OPT_TARGET_IMG%"" ^
		  -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
		  -o "ghidra trace start" ^
		  -o "ghidra trace sync-enable" ^
		  -o "ghidra trace sync-synth-stopped" ^
	      -o "%OPT_START_CMD%"
	) ELSE (
	    "%OPT_LLDB_PATH%" ^
		  -o "version" ^
		  -o "script import ghidralldb" ^
		  -o "platform select remote-android" ^
		  -o "platform connect connect://%OPT_HOST%:%OPT_PORT%" ^
		  -o "settings set target.default-arch %OPT_ARCH%"
	      -o "target create "%OPT_TARGET_IMG%"" ^
		  -o "settings set target.run-args %OPT_TARGET_ARGS%" ^
		  -o "ghidra trace connect %GHIDRA_TRACE_RMI_ADDR%" ^
		  -o "ghidra trace start" ^
		  -o "ghidra trace sync-enable" ^
		  -o "ghidra trace sync-synth-stopped" ^
	      -o "%OPT_START_CMD%"
	)
)