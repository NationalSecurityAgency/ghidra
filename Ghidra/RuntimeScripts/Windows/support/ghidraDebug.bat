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
:: Ghidra debug launch

@echo off
setlocal

:: Optionally override the default Java heap memory, which is typically 1/4 of system RAM.
:: Supported values are of the regular expression form "\d+[gGmMkK]", allowing the value to be 
:: specified in gigabytes, megabytes, or kilobytes (for example: 8G, 4096m, etc).
set MAXMEM_DEFAULT=

:: Allow the above MAXMEM_DEFAULT to be overridden by externally set environment variables
:: - GHIDRA_MAXMEM: Desired maximum heap memory for all Ghidra instances
:: - GHIDRA_GUI_MAXMEM: Desired maximum heap memory only for Ghidra GUI instances
if not defined GHIDRA_MAXMEM set "GHIDRA_MAXMEM=%MAXMEM_DEFAULT%"
if not defined GHIDRA_GUI_MAXMEM set "GHIDRA_GUI_MAXMEM=%GHIDRA_MAXMEM%"

:: Apply Java options from externally set environment variables
set VMARG_LIST=%GHIDRA_JAVA_OPTIONS% %GHIDRA_GUI_JAVA_OPTIONS%

:: Debug launch mode can be changed to one of the following:
::    debug, debug-suspend
set LAUNCH_MODE=debug

:: Set the debug address to listen on.
:: NOTE: This variable is ignored if not launching in a debugging mode.
set DEBUG_ADDRESS=127.0.0.1:18001

call "%~dp0launch.bat" %LAUNCH_MODE% jdk Ghidra "%GHIDRA_GUI_MAXMEM%" "%VMARG_LIST%" ghidra.GhidraRun %*
