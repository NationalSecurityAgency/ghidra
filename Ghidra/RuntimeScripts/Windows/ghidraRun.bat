:: Ghidra launch

@echo off
setlocal

:: Maximum heap memory size
:: Default for Windows 32-bit is 768M and 64-bit is 1024M
:: Raising the value too high may cause a silent failure where
:: Ghidra fails to launch.
:: Uncomment MAXMEM setting if non-default value is needed

::set MAXMEM=768M

call "%~dp0support\launch.bat" bg Ghidra "%MAXMEM%" "" ghidra.GhidraRun %*

