:: Ghidra Headless Analyzer launch (see analyzeHeadlessREADME.html)

@echo off

setlocal EnableDelayedExpansion

:: Maximum heap memory size.  For headless, it is recommended to not use the default value
:: because garbage collection could take too long on systems with a large amount of physical
:: memory.
set MAXMEM=2G

:: Launch mode can be changed to one of the following:
::    fg, debug, debug-suspend
set LAUNCH_MODE=fg

:: Set the debug address to listen on.
:: NOTE: This variable is ignored if not launching in a debugging mode.
set DEBUG_ADDRESS=127.0.0.1:13002

:: Limit the # of garbage collection and JIT compiler threads in case many headless
:: instances are run in parallel.  By default, Java will assign one thread per core
:: which does not scale well on servers with many cores.
set VMARG_LIST=-XX:ParallelGCThreads=2
set VMARG_LIST=%VMARG_LIST% -XX:CICompilerCount=2

:: store current path
set "filepath=%~dp0"

:: Loop through parameters (if there aren't any, just continue) and store
::   in params variable.

set params=

:Loop
if "%~1" == "" goto cont

:: If -import is found and Windows has not done proper wildcard expansion, force
:: this to happen and save expansion to params variable.
if "%~1" == "-import" (	
	set params=!params! -import
	for %%f in ("%~2") DO (
		call set params=!params! "%%~ff"
	)
	SHIFT
) else (
	set params=!params! "%~1"
)

shift
goto Loop

:cont

call "%filepath%launch.bat" %LAUNCH_MODE% Ghidra-Headless "%MAXMEM%" "%VMARG_LIST%" ghidra.app.util.headless.AnalyzeHeadless %params%
