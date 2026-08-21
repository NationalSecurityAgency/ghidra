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
:: Command-line script for interacting with a BSim database

@echo off
setlocal

:: Optionally override the default Java heap memory, which is typically 1/4 of system RAM.
:: Supported values are of the regular expression form "\d+[gGmMkK]", allowing the value to be 
:: specified in gigabytes, megabytes, or kilobytes (for example: 8G, 4096m, etc).
set MAXMEM_DEFAULT=

:: Allow the above MAXMEM_DEFAULT to be overridden by externally set environment variables
:: - GHIDRA_MAXMEM: Desired maximum heap memory for all Ghidra instances
:: - GHIDRA_BSIM_MAXMEM: Desired maximum heap memory only for Ghidra BSim instances
if not defined GHIDRA_MAXMEM set "GHIDRA_MAXMEM=%MAXMEM_DEFAULT%"
if not defined GHIDRA_BSIM_MAXMEM set "GHIDRA_BSIM_MAXMEM=%GHIDRA_MAXMEM%"

:: Apply Java options from externally set environment variables
set VMARG_LIST=%GHIDRA_JAVA_OPTIONS% %GHIDRA_BSIM_JAVA_OPTIONS%

:: launch mode  (fg, bg, debug, debug-suspend)
set LAUNCH_MODE=fg

:: Sets LAUNCH_DIR to the directory that contains this file (bsim.bat).
:: LAUNCH_DIR will not contain a trailing slash.
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
:: '~0,-1' - removes trailing \
set "LAUNCH_DIR=%~dp0"
set "LAUNCH_DIR=%LAUNCH_DIR:~0,-1%"

call "%LAUNCH_DIR%\launch.bat" %LAUNCH_MODE% jdk BSim "%GHIDRA_BSIM_MAXMEM%" "%VMARG_LIST%" ghidra.features.bsim.query.ingest.BSimLaunchable %*
