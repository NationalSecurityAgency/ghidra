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

:: ---------------------------------------------------------------------------------------
:: Ghidra Server Script (see svrREADME.html for usage details)
::   Usage: ghidraSvr [ console | status | install | uninstall | start | stop | restart ]
:: ---------------------------------------------------------------------------------------

:: The Java 21 (or later) runtime installation must either be on the system path, specified by the
:: JAVA_HOME environment variable or preferably set explicitly with the GHIDRA_JAVA_HOME variable 
:: below.  Since this script may be used during service initialization, reliance on environmental 
:: settings such as JAVA_HOME may be problematic.  It is also important to note that once installed
:: as a service, changes to this file or environmental settings may not have an affect on any service
:: registration that was generated at the time of service installation.

:: set "GHIDRA_JAVA_HOME="

:: Sets SERVER_DIR to the directory that contains this file (ghidraSvr.bat).
:: SERVER_DIR will not contain a trailing slash.
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
:: '~0,-1' - removes trailing \
set "SERVER_DIR=%~dp0"
set "SERVER_DIR=%SERVER_DIR:~0,-1%"

:: Ensure Ghidra path doesn't contain illegal characters
if not "%SERVER_DIR:!=%"=="%SERVER_DIR%" (
	echo Ghidra path cannot contain a "!" character.
	exit /B 1
)

setlocal enabledelayedexpansion

set OPTION=%1

goto lab0

:usage
	echo.
	echo Usage: %0 { console ^| start ^| stop ^| restart ^| status }
	echo.
	set DOUBLE_CLICKED=n
	for /f "tokens=2" %%# in ("%cmdcmdline%") do if /i "%%#" equ "/c" set DOUBLE_CLICKED=y
	if "!DOUBLE_CLICKED!"=="y" (
		pause
	)
	exit /B 1

:lab0

if "%OPTION%"=="" (
	goto usage
)

set IS_ADMIN=NO
whoami /groups | findstr "S-1-16-12288 " >NUL && set IS_ADMIN=YES

if "%IS_ADMIN%"=="NO" (
	:: The following command options require admin
	if "%OPTION%"=="start" goto adminFail
	if "%OPTION%"=="stop" goto adminFail
	if "%OPTION%"=="install" goto adminFail
	if "%OPTION%"=="uninstall" goto adminFail
	if "%OPTION%"=="restart" goto adminFail
)

set "APP_NAME=ghidraSvr"
set "APP_LONG_NAME=Ghidra Server"
set "MODULE_DIR=Ghidra\Features\GhidraServer"
set "WRAPPER_NAME_PREFIX=yajsw"
set "WRAPPER_TMPDIR=%TEMP%"

if exist "%SERVER_DIR%\..\Ghidra\" goto normal

:: NOTE: If adjusting JAVA command assignment - do not attempt to add parameters (e.g., -d64, -version:1.7, etc.)

:: NOTE: Variables that get accessed in server.conf must be lowercase

:: Development Environment (Eclipse classes or "gradle jar")
set "GHIDRA_HOME=%SERVER_DIR%\..\..\..\.."
set "WRAPPER_CONF=%SERVER_DIR%\..\..\Common\server\server.conf"
set "DATA_DIR=%GHIDRA_HOME%\%MODULE_DIR%\build\data"
set "CLASSPATH_FRAG=%GHIDRA_HOME%\%MODULE_DIR%\build\dev-meta\classpath.frag"
set "LS_CPATH=%GHIDRA_HOME%\GhidraBuild\LaunchSupport\bin\main"
if not exist "%LS_CPATH%" (
	set "LS_CPATH=%GHIDRA_HOME%\GhidraBuild\LaunchSupport\build\libs\LaunchSupport.jar"
)
if not exist "%LS_CPATH%" (
	set ERROR=Cannot launch from repo because Ghidra has not been compiled with Eclipse or Gradle.
	goto reportError
)

goto lab1

:normal
set "GHIDRA_HOME=%SERVER_DIR%\.."
set "WRAPPER_CONF=%SERVER_DIR%\server.conf"
set "DATA_DIR=%GHIDRA_HOME%\%MODULE_DIR%\data"
set "CLASSPATH_FRAG=%GHIDRA_HOME%\%MODULE_DIR%\data\classpath.frag"
set "LS_CPATH=%GHIDRA_HOME%\support\LaunchSupport.jar"

:lab1

:: set WRAPPER_HOME to unpacked yajsw location (crazy FOR syntax to set variable from command output)
for /F "usebackq delims=" %%p in (`dir "%DATA_DIR%" /ad /b ^| findstr "^%WRAPPER_NAME_PREFIX%"`) do set WRAPPER_DIRNAME=%%p
set "WRAPPER_HOME=%DATA_DIR%\%WRAPPER_DIRNAME%"

if not exist "%WRAPPER_HOME%\" (
	echo.
	echo %WRAPPER_NAME_PREFIX% not found
	echo.
	exit /B 1
)

echo Using service wrapper: %WRAPPER_DIRNAME%

:: Check for use of GHIDRA_JAVA_HOME
if not defined GHIDRA_JAVA_HOME goto findJava

set "java=%GHIDRA_JAVA_HOME%\bin\java.exe"
"%java%" -version >NUL 2>&1
if %ERRORLEVEL% neq 0 (
    set ERROR=The ghidraSvr.bat script GHIDRA_JAVA_HOME variable is set to an invalid directory: %GHIDRA_JAVA_HOME%
    goto reportError
)

:: Check specified GHIDRA_JAVA_HOME
"%java%" -cp "%LS_CPATH%" LaunchSupport "%GHIDRA_HOME%" -java_home_check "%GHIDRA_JAVA_HOME%"
if %ERRORLEVEL% neq 0 ( 
    set ERROR=The ghidraSvr script GHIDRA_JAVA_HOME variable specifies an invalid or unsupported Java runtime: %GHIDRA_JAVA_HOME%
    goto reportError
)

:: Bypass LaunchSupport java search when GHIDRA_JAVA_HOME is specified
goto lab3

:findJava

:: check for java based upon PATH
set java=java.exe
java.exe -version >NUL 2>&1
if %ERRORLEVEL% equ 0 goto lab2

:: check for java based upon JAVA_HOME environment variable
if not defined JAVA_HOME goto javaNotFound
set "java=%JAVA_HOME%\bin\java.exe"
"%java%" -version >NUL 2>&1
if %ERRORLEVEL% equ 0 goto lab2
echo WARNING: JAVA_HOME environment variable is set to an invalid directory: %JAVA_HOME%

:javaNotFound
set ERROR=The ghidraSvr.bat script GHIDRA_JAVA_HOME variable is not set and 'java' command could not be found in your PATH or with JAVA_HOME.
goto reportError

:: Use LaunchSupport to locate supported java runtime
:lab2

:: Get the java that will be used to launch GhidraServer
set LS_JAVA_HOME=
for /f "delims=*" %%i in ('call "%java%" -cp "%LS_CPATH%" LaunchSupport "%GHIDRA_HOME%" -java_home') do set LS_JAVA_HOME=%%i
if "%LS_JAVA_HOME%" == "" (
	set ERROR=Unable to find a supported Java runtime on your system.
	goto reportError
)

:: reestablish JAVA path based upon LS_JAVA_HOME
set "java=%LS_JAVA_HOME%\bin\java.exe"

:: execute command OPTION
:lab3

set VMARGS=-Djava.io.tmpdir="%WRAPPER_TMPDIR%"
set VMARGS=%VMARGS% -Djna_tmpdir="%WRAPPER_TMPDIR%"

:: set DEBUG=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:18888

if "%OPTION%"=="console" (
	start "%APP_LONG_NAME%" "%java%" %VMARGS% %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -c "%WRAPPER_CONF%"
	echo Use Ctrl-C in Ghidra Console to terminate...
	
) else if "%OPTION%"=="status" (
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -q "%WRAPPER_CONF%"

) else if "%OPTION%"=="start" (
	"%java%" %VMARGS% %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"

) else if "%OPTION%"=="stop" (
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -p "%WRAPPER_CONF%"

) else if "%OPTION%"=="restart" (
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -p "%WRAPPER_CONF%"
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"

) else if "%OPTION%"=="install" (
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -i "%WRAPPER_CONF%"
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"
	
) else if "%OPTION%"=="uninstall" (
	"%java%" %VMARGS% -jar "%WRAPPER_HOME%/wrapper.jar" -r "%WRAPPER_CONF%"

) else (
	goto usage
)

goto eof

:adminFail
	echo.
	echo Command option "%OPTION%" must be run as an Administrator (using Administrator CMD shell - see svrREADME.txt)
	echo.
	exit /B 1
	
:reportError
	echo.
	echo ERROR: %ERROR%
	echo Please refer to the svrREADME documentation.
	echo.
	echo ERROR: %ERROR% >> %GHIDRA_HOME%\wrapper.log
	exit /B 1

:eof
