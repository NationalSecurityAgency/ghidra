:: Command-line script for interacting with a BSim database

@echo off
setlocal

:: Maximum heap memory may be changed if default is inadequate. This will generally be up to 1/4 of 
:: the physical memory available to the OS. Uncomment MAXMEM setting if non-default value is needed.
::set MAXMEM=2G

:: launch mode  (fg, bg, debug, debug-suspend)
set LAUNCH_MODE=fg

:: Sets LAUNCH_DIR to the directory that contains this file (bsim.bat).
:: LAUNCH_DIR will not contain a trailing slash.
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
:: '~0,-1' - removes trailing \
set "LAUNCH_DIR=%~dp0"
set "LAUNCH_DIR=%LAUNCH_DIR:~0,-1%"

call "%LAUNCH_DIR%\launch.bat" %LAUNCH_MODE% jdk BSim "%MAXMEM%" "" ghidra.features.bsim.query.ingest.BSimLaunchable %*
