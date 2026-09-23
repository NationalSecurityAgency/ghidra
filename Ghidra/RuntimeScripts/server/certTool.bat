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
@echo off

setlocal

:: maximum heap memory may be change if inadequate
set MAXMEM=128M

:: Sets SCRIPT_DIR to the directory that contains this file
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
set "SCRIPT_DIR=%~dp0"

set VMARGS=-DCertTool.invocation=%~n0 -Djava.awt.headless=true

call "%~dp0\..\support\launch.bat" fg jre certTool "%MAXMEM%" "%VMARGS%" ghidra.net.CertTool %*
