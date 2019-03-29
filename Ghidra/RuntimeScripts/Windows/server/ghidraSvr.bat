@echo off

rem ---------------------------------------------------------------------------------------
rem Ghidra Server Script (see svrREADME.html for usage details)
rem   Usage: ghidraSvr [ console | status | install | uninstall | start | stop | restart ]
rem ---------------------------------------------------------------------------------------

rem  The Java 11 (or later) runtime installation must either be on the system path or identified
rem  by setting the JAVA_HOME environment variable.  If not using a formally installed Java 
rem  runtime which has been configured into the system PATH ahead of other Java installations
rem  it may be necessary to explicitly specify the path to the installation by setting JAVA_HOME
rem  below:

rem set JAVA_HOME=

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
	rem The following command options require admin
	if "%OPTION%"=="start" goto adminFail
	if "%OPTION%"=="stop" goto adminFail
	if "%OPTION%"=="install" goto adminFail
	if "%OPTION%"=="uninstall" goto adminFail
	if "%OPTION%"=="restart" goto adminFail
)

rem Find the script directory
rem %~dsp0 is location of current script under NT
set _REALPATH=%~dp0

set APP_NAME=ghidraSvr
set APP_LONG_NAME=Ghidra Server

set MODULE_DIR=Ghidra\Features\GhidraServer

set WRAPPER_NAME_PREFIX=yajsw

if exist "%_REALPATH%..\Ghidra\" goto normal

rem NOTE: If adjusting JAVA command assignment - do not attempt to add parameters (e.g., -d64, -version:1.7, etc.)

rem Development Environment
set GHIDRA_HOME=%_REALPATH%..\..\..\..
set WRAPPER_CONF=%_REALPATH%..\..\Common\server\server.conf
set DATA_DIR=%GHIDRA_HOME%\%MODULE_DIR%\build\data
set CLASSPATH_FRAG=%GHIDRA_HOME%\%MODULE_DIR%\build\dev-meta\classpath.frag
set LS_CPATH=%GHIDRA_HOME%\GhidraBuild\LaunchSupport\bin\main

goto lab1

:normal
set GHIDRA_HOME=%_REALPATH%..
set WRAPPER_CONF=%_REALPATH%server.conf
set DATA_DIR=%GHIDRA_HOME%\%MODULE_DIR%\data
set CLASSPATH_FRAG=%GHIDRA_HOME%\%MODULE_DIR%\data\classpath.frag
set LS_CPATH=%GHIDRA_HOME%\support\LaunchSupport.jar

:lab1

rem set WRAPPER_HOME to unpacked yajsw location (crazy FOR syntax to set variable from command output)
for /F "usebackq delims=" %%p in (`dir "%DATA_DIR%" /ad /b ^| findstr "^%WRAPPER_NAME_PREFIX%"`) do set WRAPPER_DIRNAME=%%p
set WRAPPER_HOME=%DATA_DIR%\%WRAPPER_DIRNAME%

if not exist "%WRAPPER_HOME%\" (
	echo.
	echo %WRAPPER_NAME_PREFIX% not found
	echo.
	exit /B 1
)

echo Using service wrapper: %WRAPPER_DIRNAME%

rem Find java.exe
if defined JAVA_HOME goto findJavaFromJavaHome

set JAVA=java.exe
%JAVA% -version >NUL 2>&1
if "%ERRORLEVEL%" == "0" goto lab2
set ERROR=ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
goto reportError

:findJavaFromJavaHome
set JAVA_HOME=%JAVA_HOME:"=%
set JAVA=%JAVA_HOME%\bin\java.exe

if exist "%JAVA%" goto lab2
set ERROR=ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
goto reportError

:lab2

:: Get the java that will be used to launch GhidraServer
set JAVA_HOME=
for /f "delims=*" %%i in ('call "%JAVA%" -cp "%LS_CPATH%" LaunchSupport "%GHIDRA_HOME%" -java_home') do set JAVA_HOME=%%i
if "%JAVA_HOME%" == "" (
	set ERROR=Failed to find a supported Java runtime.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
	goto reportError
)

rem reestablish JAVA path based upon final JAVA_HOME
set JAVA=%JAVA_HOME%\bin\java.exe

set OS_NAME=win32
"%JAVA%" -version 2>&1 | findstr /I " 64-Bit " >NUL
if errorlevel 0 (
	set OS_NAME=win64
)

set OS_DIR=%GHIDRA_HOME%\%MODULE_DIR%\os\%OS_NAME%

:: set DEBUG=-Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=*:18888

if "%OPTION%"=="console" (
	start "%APP_LONG_NAME%" "%JAVA%" %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -c "%WRAPPER_CONF%"
	echo Use Ctrl-C in Ghidra Console to terminate...
	
) else if "%OPTION%"=="status" (
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -q "%WRAPPER_CONF%"

) else if "%OPTION%"=="start" (
	"%JAVA%" %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"

) else if "%OPTION%"=="stop" (
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -p "%WRAPPER_CONF%"

) else if "%OPTION%"=="restart" (
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -p "%WRAPPER_CONF%"
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"

) else if "%OPTION%"=="install" (
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -i "%WRAPPER_CONF%"
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -t "%WRAPPER_CONF%"
	
) else if "%OPTION%"=="uninstall" (
	"%JAVA%" -jar "%WRAPPER_HOME%/wrapper.jar" -r "%WRAPPER_CONF%"

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
	echo %ERROR%
	echo.
	echo %ERROR% >> %GHIDRA_HOME%\wrapper.log
	exit /B 1

:eof
