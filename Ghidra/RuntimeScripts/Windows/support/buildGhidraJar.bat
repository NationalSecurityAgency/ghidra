:: ###
:: IP: GHIDRA
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
:: ##
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
