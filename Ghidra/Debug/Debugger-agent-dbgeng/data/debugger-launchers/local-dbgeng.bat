::@title dbgeng
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>dbgeng</tt> (in a Python interpreter)</h3>
::@desc   <p>This will launch the target on the local machine using <tt>dbgeng.dll</tt>. Typically,
::@desc   Windows systems have this library pre-installed, but it may have limitations, e.g., you
::@desc   cannot use <tt>.server</tt>. For the full capabilities, you must install WinDbg.</p>
::@desc   <p>Furthermore, you must have Python 3 installed on your system, and it must have the
::@desc   <tt>pybag</tt> and <tt>protobuf</tt> packages installed.</p>
::@desc </body></html>
::@menu-group local
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#dbgeng
::@env OPT_PYTHON_EXE:str="python" "Path to python" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
:: Use env instead of args, because "all args except first" is terrible to implement in batch
::@env OPT_TARGET_IMG:str="" "Image" "The target binary executable image"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"

@echo off

if exist "%GHIDRA_HOME%\ghidra\.git\" (
  set PYTHONPATH=%GHIDRA_HOME%\ghidra\Ghidra\Debug\Debugger-agent-dbgeng\build\pypkg\src;%PYTHONPATH%
  set PYTHONPATH=%GHIDRA_HOME%\ghidra\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src;%PYTHONPATH%
) else if exist "%GHIDRA_HOME%\.git\" (
  set PYTHONPATH=%GHIDRA_HOME%\Ghidra\Debug\Debugger-agent-dbgeng\build\pypkg\src;%PYTHONPATH%
  set PYTHONPATH=%GHIDRA_HOME%\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src;%PYTHONPATH%
) else (
  set PYTHONPATH=%GHIDRA_HOME%\Ghidra\Debug\Debugger-agent-dbgeng\pypkg\src;%PYTHONPATH%
  set PYTHONPATH=%GHIDRA_HOME%\Ghidra\Debug\Debugger-rmi-trace\pypkg\src;%PYTHONPATH%
)

echo PYTHONPATH is %PYTHONPATH%
echo OPT_TARGET_IMG is [%OPT_TARGET_IMG%]

"%OPT_PYTHON_EXE%" -i ..\support\local-dbgeng.py
