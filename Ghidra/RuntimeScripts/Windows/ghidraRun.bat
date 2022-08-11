:: Ghidra launch

@echo off
setlocal

:: Maximum heap memory may be changed if default is inadequate. This will generally be up to 1/4 of 
:: the physical memory available to the OS. Uncomment MAXMEM setting if non-default value is needed.
::set MAXMEM=2G

call "%~dp0support\launch.bat" bg jdk Ghidra "%MAXMEM%" "" ghidra.GhidraRun %*

