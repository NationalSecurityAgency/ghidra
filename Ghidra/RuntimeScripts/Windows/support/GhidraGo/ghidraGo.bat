:: GhidraGo launch

@echo off
setlocal

set SCRIPT_FILE=%~dp0%
:: in dev mode, SCRIPT_FILE is Ghidra/RuntimeScripts_U/Windows/support/GhidraGo/ghidraGo
:: in release mode, SCRIPT_FILE is support/GhidraGo/ghidraGo
:: BASE_DIR is the base directory of ext-u
:: Initially assume to be in release mode.
set BASE_DIR=%SCRIPT_FILE:~0,-1%\..\..

if not exist %BASE_DIR%\Ghidra (
	:: set base dir to location of windows base script dir
	set BASE_DIR=%BASE_DIR%\..\..\..\..\ghidra\Ghidra\RuntimeScripts\Windows
)

call "%BASE_DIR%\support\launch.bat" fg jdk GhidraGo "" "" ghidra.GhidraGo "%*"

