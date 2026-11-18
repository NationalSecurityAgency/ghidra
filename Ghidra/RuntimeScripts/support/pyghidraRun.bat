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
:: PyGhidra launch

@echo off
setlocal enabledelayedexpansion

:: See if we were doubled clicked or run from a command prompt
set DOUBLE_CLICKED=n
for /f "tokens=2" %%# in ("%cmdcmdline%") do if /i "%%#" equ "/c" set DOUBLE_CLICKED=y

:: Optionally override the default Java heap memory, which is typically 1/4 of system RAM.
:: Supported values are of the regular expression form "\d+[gGmMkK]", allowing the value to be
:: specified in gigabytes, megabytes, or kilobytes (for example: 8G, 4096m, etc).
set MAXMEM_DEFAULT=

:: Allow the above MAXMEM_DEFAULT to be overridden by externally set environment variables
:: - GHIDRA_MAXMEM: Desired maximum heap memory for all Ghidra instances
:: - GHIDRA_GUI_MAXMEM: Desired maximum heap memory only for Ghidra GUI instances
:: - GHIDRA_HEADLESS_MAXMEM: Desired maximum heap memory only for headless Ghidra instances
if not defined GHIDRA_MAXMEM set "GHIDRA_MAXMEM=%MAXMEM_DEFAULT%"
if not defined GHIDRA_GUI_MAXMEM set "GHIDRA_GUI_MAXMEM=%GHIDRA_MAXMEM%"
if not defined GHIDRA_HEADLESS_MAXMEM set "GHIDRA_HEADLESS_MAXMEM=%GHIDRA_MAXMEM%"

:: Use the headless maximum heap memory if launching in headless mode
:: NOTE: "shift" does not affect %*, so all arguments are still passed along below
set "MAXMEM=%GHIDRA_GUI_MAXMEM%"
:check_headless
if "%~1"=="" goto check_headless_done
if /i "%~1"=="-H" goto use_headless
if /i "%~1"=="--headless" goto use_headless
shift
goto check_headless
:use_headless
set "MAXMEM=%GHIDRA_HEADLESS_MAXMEM%"
:check_headless_done

:: Since JPype doesn't seem to pick up JDK_JAVA_OPTIONS automatically, include it ourselves
set VMARG_LIST=%JDK_JAVA_OPTIONS%

:: Apply the maximum heap memory, if specified
if defined MAXMEM set VMARG_LIST=%VMARG_LIST% -Xmx%MAXMEM%

:: Apply Java options from externally set environment variables
set VMARG_LIST=%VMARG_LIST% %GHIDRA_JAVA_OPTIONS% %PYGHIDRA_JAVA_OPTIONS% -Dsun.java2d.dpiaware=true

:: Make sure Python3 is installed
set PYTHON=py
where /q %PYTHON%
if not %ERRORLEVEL% == 0 (
	set PYTHON=python
	where /q !PYTHON!
	if not !ERRORLEVEL! == 0 (
		echo Python 3 is not installed.
		goto exit1
	)
)

:: Dev mode or production mode?
set DEV_ARG=
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "INSTALL_DIR=%SCRIPT_DIR%\.."
if not exist "%INSTALL_DIR%\Ghidra" (
	set DEV_ARG="--dev"
	set "INSTALL_DIR=%SCRIPT_DIR%\..\..\.."
)

set "PYGHIDRA_LAUNCHER=%INSTALL_DIR%\Ghidra\Features\PyGhidra\support\pyghidra_launcher.py

%PYTHON% "%PYGHIDRA_LAUNCHER%" "%INSTALL_DIR%" %DEV_ARG% %VMARG_LIST% %*

:exit1
if not %ERRORLEVEL% == 0 (
	if "%DOUBLE_CLICKED%"=="y" (
		pause
	)
)

exit /B %ERRORLEVEL%
