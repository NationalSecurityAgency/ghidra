:: Ghidra Sleigh language compiler launch

@echo off
setlocal

:: maximum heap memory may be change if inadequate
set MAXMEM=256M

call "%~dp0launch.bat" fg Sleigh "%MAXMEM%" "" ghidra.pcodeCPort.slgh_compile.SleighCompileLauncher %*
