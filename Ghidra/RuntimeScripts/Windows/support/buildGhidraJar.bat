:: Ghidra Jar Builder launch 

@echo off
setlocal

:: launch mode can be changed to one of the following:
::    fg, debug, debug-suspend
set LAUNCH_MODE=fg

:: Sets SCRIPT_DIR to the directory that contains this file (ends with '\')
set "SCRIPT_DIR=%~dp0"

set "GHIDRA_ROOT_DIR=%SCRIPT_DIR%..\Ghidra"
if exist "%GHIDRA_ROOT_DIR%" goto continue

echo This script does not support development mode use
exit /B 1

:continue

set APP_VMARGS=-DGhidraJarBuilder.Name=%~n0

call "%~dp0launch.bat" %LAUNCH_MODE% Ghidra "" "%APP_VMARGS%" ghidra.util.GhidraJarBuilder -main ghidra.JarRun %*
