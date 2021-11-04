:: Ghidra debug launch

@echo off
setlocal

:: Maximum heap memory may be changed if default is inadequate. This will generally be up to 1/4 of 
:: the physical memory available to the OS. Uncomment MAXMEM setting if non-default value is needed.
::set MAXMEM=2G

:: Debug launch mode can be changed to one of the following:
::    debug, debug-suspend
set LAUNCH_MODE=debug

:: Set the debug address to listen on.
:: NOTE: This variable is ignored if not launching in a debugging mode.
set DEBUG_ADDRESS=127.0.0.1:18001

call "%~dp0launch.bat" %LAUNCH_MODE% Ghidra "%MAXMEM%" "" ghidra.GhidraRun %*
