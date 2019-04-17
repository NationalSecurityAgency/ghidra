:: Ghidra debug launch

@echo off
setlocal

:: Maximum heap memory size
:: Default for Windows 32-bit is 768M and 64-bit is 1024M
:: Raising the value too high may cause a silent failure where
:: Ghidra fails to launch.
:: Uncomment MAXMEM setting if non-default value is needed

::set MAXMEM=768M

:: Debug launch mode can be changed to one of the following:
::    debug, debug-suspend
set LAUNCH_MODE=debug

:: Set the debug address to listen on.
:: NOTE: This variable is ignored if not launching in a debugging mode.
set DEBUG_ADDRESS=127.0.0.1:18001

call "%~dp0launch.bat" %LAUNCH_MODE% Ghidra "%MAXMEM%" "" ghidra.GhidraRun %*
