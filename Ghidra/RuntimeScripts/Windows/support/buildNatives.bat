:: Build Native Binaries
::
:: args: forwarded to gradle (-i, -s, etc)

@echo off

:: See if we were doubled clicked or run from a command prompt
set DOUBLE_CLICKED=n
for /f "tokens=2" %%# in ("%cmdcmdline%") do if /i "%%#" equ "/c" set DOUBLE_CLICKED=y

:: Make sure gradle is on the path
call gradle -h >nul 2>nul
if not %ERRORLEVEL% == 0 (
	echo Gradle not found on the PATH
	goto exit
)

echo Building natives in Ghidra...
pushd "%~dp0..\Ghidra"
call gradle %* buildNatives
popd
if not %ERRORLEVEL% == 0 (
	goto exit
)

echo Building natives in GPL...
pushd "%~dp0..\GPL"
call gradle %* buildNatives
popd
if not %ERRORLEVEL% == 0 (
	goto exit
)

:exit
if "%DOUBLE_CLICKED%"=="y" (
	pause
)

exit /B %ERRORLEVEL%
