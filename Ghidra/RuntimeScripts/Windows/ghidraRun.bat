@echo off
setlocal

REM Maximum heap memory calculation based on available system resources
for /f "tokens=2 delims==" %%I in ('wmic OS | findstr /i "TotalVisibleMemorySize"') do set "TotalMemory=%%I"
set /a "MAXMEM=TotalMemory / 4194304"  REM Allocating 1/4th of total memory (in bytes), adjust divisor as needed

call "%~dp0support\launch.bat" bg jdk Ghidra "%MAXMEM%G" "" ghidra.GhidraRun %*

REM Error handling
if errorlevel 1 (
    echo There was an issue launching Ghidra. Please check your configuration and try again.
    exit /b 1
)

REM Successful launch
exit /b 0
