::@title qemu-system + gdb
::@image-opt env:OPT_TARGET_IMG
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>qemu-system</tt> and connect with <tt>gdb</tt></h3>
::@desc   <p>
::@desc     This will launch the target on the local machine using <tt>qemu-system</tt>.
::@desc     Then in a second terminal, it will connect <tt>gdb</tt> to QEMU's GDBstub.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group cross
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#gdb_qemu
::@env OPT_TARGET_IMG:file!="" "Image" "The target binary executable image"
::@env GHIDRA_LANG_EXTTOOL_qemu_system:file="" "QEMU command" "The path to qemu-system for the target architecture."
::@env QEMU_GDB:int=1234 "QEMU Port" "Port for gdb connection to qemu"
::@env OPT_EXTRA_QEMU_ARGS:str="" "Extra qemu arguments" "Extra arguments to pass to qemu. Use with care."
::@env OPT_GDB_PATH:file="gdb-multiarch" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
::@env OPT_EXTRA_TTY:bool=false "QEMU TTY" "Provide a separate terminal emulator for qemu."

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

IF "%OPT_EXTRA_TTY%"=="true" (
  start "qemu" "%GHIDRA_LANG_EXTTOOL_qemu%" %OPT_EXTRA_QEMU_ARGS% -gdb tcp::%QEMU_GDB% -S "%OPT_TARGET_IMG%"
) ELSE (
  start /B "qemu" "%GHIDRA_LANG_EXTTOOL_qemu%" %OPT_EXTRA_QEMU_ARGS% -gdb tcp::%QEMU_GDB% -S "%OPT_TARGET_IMG%"
)

:: Give QEMU a moment to open the socket
powershell -nop -c "& {sleep -m 100}"

"%OPT_GDB_PATH%" ^
  -q ^
  -ex "set pagination off" ^
  -ex "set confirm off" ^
  -ex "show version" ^
  -ex "python import ghidragdb" ^
  -ex "target exec '%OPT_TARGET_IMG%'" ^
  -ex "ghidra trace connect '%GHIDRA_TRACE_RMI_ADDR%'" ^
  -ex "ghidra trace start" ^
  -ex "ghidra trace sync-enable" ^
  -ex "target remote localhost:%QEMU_GDB%" ^
  -ex "set confirm on" ^
  -ex "set pagination on"
