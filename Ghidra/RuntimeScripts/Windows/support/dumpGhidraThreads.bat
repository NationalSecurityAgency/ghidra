:: Ghidra Debug Thread Dumper launch
:: 
:: This script will only work if Ghidra is running in debug mode (i.e., launched from
:: ghidraDebug batch file or shell script).
::

@echo off
setlocal

:: maximum heap memory may be change if inadequate
set MAXMEM=64M

:: Assumes application is utilizing debug port 18001 (change if needed)
:: NOTE: By default, ghidraDebug uses debug port 18001 and analyzeHeadless uses 13002

call "%~dp0launch.bat" fg ThreadDump "%MAXMEM%" "" util.DebugThreadDumper 18001

pause
