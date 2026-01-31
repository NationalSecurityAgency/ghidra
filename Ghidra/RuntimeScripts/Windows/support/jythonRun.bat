:: ###
:: IP: GHIDRA
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
:: ##
:: Ghidra jython launch

@echo off
setlocal

:: Optionally override the default Java heap memory, which is typically 1/4 of system RAM.
:: Supported values are of the regular expression form "\d+[gGmMkK]", allowing the value to be 
:: specified in gigabytes, megabytes, or kilobytes (for example: 8G, 4096m, etc).
set MAXMEM_DEFAULT=

:: Allow the above MAXMEM_DEFAULT to be overridden by externally set environment variables
:: - GHIDRA_MAXMEM: Desired maximum heap memory for all Ghidra instances
:: - GHIDRA_JYTHON_MAXMEM: Desired maximum heap memory only for Ghidra Jython instances
if not defined GHIDRA_MAXMEM set "GHIDRA_MAXMEM=%MAXMEM_DEFAULT%"
if not defined GHIDRA_JYTHON_MAXMEM set "GHIDRA_JYTHON_MAXMEM=%GHIDRA_MAXMEM%"

:: Limit the # of garbage collection and JIT compiler threads in case many headless
:: instances are run in parallel.  By default, Java will assign one thread per core
:: which does not scale well on servers with many cores.
set VMARG_LIST=-XX:ParallelGCThreads=2 -XX:CICompilerCount=2

:: Apply Java options from externally set environment variables
set VMARG_LIST=%VMARG_LIST% %GHIDRA_JAVA_OPTIONS% %GHIDRA_JYTHON_JAVA_OPTIONS%

:: Launch mode can be changed to one of the following:
::    fg, debug, debug-suspend
set LAUNCH_MODE=fg

:: Set the debug address to listen on.
:: NOTE: This variable is ignored if not launching in a debugging mode.
set DEBUG_ADDRESS=127.0.0.1:13002

call "%~dp0launch.bat" %LAUNCH_MODE% jdk Ghidra-Jython "%GHIDRA_JYTHON_MAXMEM%" "%VMARG_LIST%" ghidra.jython.JythonRun %*
