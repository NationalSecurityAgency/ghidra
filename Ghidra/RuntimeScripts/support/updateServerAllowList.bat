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
:: Update Server Allow List launch

@echo off
setlocal

:: maximum heap memory may be change if inadequate
set MAXMEM=128M

set APP_VMARGS=-DUpdateServerAllowList.Name=%~n0

call "%~dp0launch.bat" fg jdk updateServerAllowList "%MAXMEM%" "%APP_VMARGS%" ghidra.app.util.headless.UpdateServerAllowList %*
