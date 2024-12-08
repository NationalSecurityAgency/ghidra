:: GhidraGo launch

@echo off
setlocal

:: Launch mode can be changed to one of the following:
::    fg, debug, debug-suspend
set LAUNCH_MODE=fg

call "%~dp0..\launch.bat" %LAUNCH_MODE% jdk GhidraGo "" "" ghidra.GhidraGo "%*"
