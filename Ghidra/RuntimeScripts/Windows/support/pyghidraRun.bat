:: PyGhidra launch

@echo off
setlocal enabledelayedexpansion

:: See if we were doubled clicked or run from a command prompt
set DOUBLE_CLICKED=n
for /f "tokens=2" %%# in ("%cmdcmdline%") do if /i "%%#" equ "/c" set DOUBLE_CLICKED=y

:: Add optional JVM args inside the quotes
set VMARG_LIST=-Dsun.java2d.dpiaware=true

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
	set "INSTALL_DIR=%SCRIPT_DIR%\..\..\..\.."
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
