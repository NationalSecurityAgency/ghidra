::@timeout 60000
::@title gdb + gdbserver via ssh
::@image-opt env:OPT_TARGET_IMG
::@desc <html><body width="300px">
::@desc   <h3>Launch with local <tt>gdb</tt> and <tt>gdbserver</tt> via <tt>ssh</tt></h3>
::@desc   <p>
::@desc     This will start <tt>gdb</tt> on the local system and then use it to connect and launch the target in <tt>gdbserver</tt> on the remote system via <tt>ssh</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group remote
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#gdb_gdbserver_ssh
::@env OPT_TARGET_IMG:str!="" "Image" "The target binary executable image on the remote system"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_SSH_PATH:file="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
::@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
::@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
::@env OPT_GDBSERVER_PATH:str="gdbserver" "gdbserver command (remote)" "The path to gdbserver on the remote system. Omit the full path to resolve using the system PATH."
::@env OPT_EXTRA_GDBSERVER_ARGS:str="" "Extra gdbserver arguments" "Extra arguments to pass to gdbserver. Use with care."
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
  -ex "target remote | '%OPT_SSH_PATH%' %OPT_EXTRA_SSH_ARGS% '%OPT_HOST%' '%OPT_GDBSERVER_PATH%' %OPT_EXTRA_GDBSERVER_ARGS% - '%OPT_TARGET_IMG%' %OPT_TARGET_ARGS%" ^
  -ex "ghidra trace connect '%GHIDRA_TRACE_RMI_ADDR%'" ^
  -ex "ghidra trace start" ^
  -ex "ghidra trace sync-enable" ^
  -ex "ghidra trace sync-synth-stopped" ^
  -ex "set confirm on" ^
  -ex "set pagination on"
