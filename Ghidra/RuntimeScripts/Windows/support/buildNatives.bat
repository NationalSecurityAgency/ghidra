:: Build Native Binaries
::
:: args: forwarded to gradle (-i, -s, etc)

@echo off

:: Make sure gradle is on the path
call gradle -h >nul 2>nul
if not %ERRORLEVEL% == 0 (
	echo Gradle not found on the PATH
	exit /B 1
)

echo Building natives in Ghidra...
pushd "%~dp0..\Ghidra"
call gradle %* buildNatives
popd

echo Building natives in GPL...
pushd "%~dp0..\GPL"
call gradle %* buildNatives
popd
