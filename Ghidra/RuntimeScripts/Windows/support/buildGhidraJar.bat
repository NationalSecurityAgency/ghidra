:: Ghidra Jar Builder launch 

@echo off
setlocal

:: launch mode can be changed to one of the following:
::    fg, debug, debug-suspend
set LAUNCH_MODE=fg

:: Sets SUPPORT_DIR to the directory that contains this file (buildGhidraJar.bat).
:: SUPPORT_DIR will not contain a trailing slash.
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
:: '~0,-1' - removes trailing \
set "SUPPORT_DIR=%~dp0"
set "SUPPORT_DIR=%SUPPORT_DIR:~0,-1%"

set "GHIDRA_ROOT_DIR=%SUPPORT_DIR%\..\Ghidra"
if exist "%GHIDRA_ROOT_DIR%" goto continue

echo This script does not support development mode use
exit /B 1

:continue

set APP_VMARGS=-DGhidraJarBuilder.Name=%~n0

call "%SUPPORT_DIR%\launch.bat" %LAUNCH_MODE% jdk Ghidra "" "%APP_VMARGS%" ghidra.util.GhidraJarBuilder -main ghidra.JarRun %*
