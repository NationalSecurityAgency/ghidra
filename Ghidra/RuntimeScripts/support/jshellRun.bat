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
:: Ghidra JShell launch

@echo off
setlocal

:: Optionally override the default Java heap memory, which is typically 1/4 of system RAM.
:: Supported values are of the regular expression form "\d+[gGmMkK]", allowing the value to be 
:: specified in gigabytes, megabytes, or kilobytes (for example: 8G, 4096m, etc).
set MAXMEM_DEFAULT=

:: Allow the above MAXMEM_DEFAULT to be overridden by externally set environment variables
:: - GHIDRA_MAXMEM: Desired maximum heap memory for all Ghidra instances
:: - GHIDRA_JSHELL_MAXMEM: Desired maximum heap memory only for JShell Ghidra instances
if not defined GHIDRA_MAXMEM set "GHIDRA_MAXMEM=%MAXMEM_DEFAULT%"
if not defined GHIDRA_JSHELL_MAXMEM set "GHIDRA_JSHELL_MAXMEM=%GHIDRA_MAXMEM%"

:: Apply Java options from externally set environment variables
set VMARG_LIST=%GHIDRA_JAVA_OPTIONS% %GHIDRA_JSHELL_JAVA_OPTIONS%

call "%~dp0launch.bat" fg jdk Ghidra-JShell "%GHIDRA_JSHELL_MAXMEM%" "%VMARG_LIST%" ghidra.JShellRun %*

