@echo off
goto continue

:showUsage
echo Usage: %0 ^<mode^> ^<java-type^> ^<name^> ^<max-memory^> "<vmarg-list>" ^<app-classname^> ^<app-args^>... 
echo    ^<mode^>: fg    run as foreground process in current shell
echo            bg    run as background process in new shell
echo            debug run as foreground process in current shell in debug mode ^(suspend=n^)
echo            debug-suspend   run as foreground process in current shell in debug mode ^(suspend=y^)
echo            NOTE: for all debug modes environment variable DEBUG_ADDRESS may be set to 
echo                  override default debug address of 127.0.0.1:18001
echo    ^<java-type^>: jdk  requires JDK to run
echo                 jre  JRE is sufficient to run (JDK works too)
echo    ^<name^>: application name used for naming console window
echo    ^<max-memory^>: maximum memory heap size in MB ^(e.g., 768M or 2G^).  Use "" if default should be used.
echo                  This will generally be upto 1/4 of the physical memory available to the OS.  On 
echo                  some systems the default could be much less (particularly for 32-bit OS).
echo    ^<vmarg-list^>: pass-thru args ^(e.g.,  "-Xmx512M -Dmyvar=1 -DanotherVar=2"^) - use
echo                  empty "" if vmargs not needed
echo    ^<app-classname^>: application classname ^(e.g., ghidra.GhidraRun ^)
echo    ^<app-args^>...: arguments to be passed to the application
echo.
echo    Example: 
echo       %0 debug jdk Ghidra 4G "" ghidra.GhidraRun
exit /B 1

:continue

:: See if we were doubled clicked or run from a command prompt
set DOUBLE_CLICKED=n
for /f "tokens=2" %%# in ("%cmdcmdline%") do if /i "%%#" equ "/c" set DOUBLE_CLICKED=y

:: Sets SUPPORT_DIR to the directory that contains this file (launch.bat).
:: SUPPORT_DIR will not contain a trailing slash.
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
:: '~0,-1' - removes trailing \
set "SUPPORT_DIR=%~dp0"
set "SUPPORT_DIR=%SUPPORT_DIR:~0,-1%"

:: Ensure Ghidra path doesn't contain illegal characters
if not "%SUPPORT_DIR:!=%"=="%SUPPORT_DIR%" (
	echo ERROR: Ghidra path cannot contain a "!" character.
	set ERRORLEVEL=1
	goto exit1
)

:: Delay the expansion of our loop items below since the value is being updated as the loop works
setlocal enabledelayedexpansion

::
:: Parse arguments
::
set VMARG_LIST=
set ARGS=
set /A INDEX=0
:shift_loop
SET ARG=%1
IF DEFINED ARG (
    set /A INDEX+=1
    if "!INDEX!"=="1" ( set MODE=%~1
    ) else if "!INDEX!"=="2" ( if "%~1" == "jre" (set JAVA_TYPE_ARG=-java_home) else (set JAVA_TYPE_ARG=-jdk_home)
    ) else if "!INDEX!"=="3" ( set APPNAME=%~1
    ) else if "!INDEX!"=="4" ( set MAXMEM=%~1
    ) else if "!INDEX!"=="5" ( if not "%~1"=="" set VMARG_LIST=%~1
    ) else if "!INDEX!"=="6" ( set CLASSNAME=%~1
    ) else set ARGS=!ARGS! "%~1"
    
    SHIFT
    GOTO shift_loop
)

if not "%CLASSNAME%" == "" (goto continue1)
echo ERROR: Incorrect launch usage - missing argument^(s^)
goto showUsage

:continue1

::
:: Production Environment
::
set "INSTALL_DIR=%SUPPORT_DIR%\.."
set "CPATH=%INSTALL_DIR%\Ghidra\Framework\Utility\lib\Utility.jar"
set "LS_CPATH=%SUPPORT_DIR%\LaunchSupport.jar"
set "DEBUG_LOG4J=%SUPPORT_DIR%\debug.log4j.xml"

if exist "%INSTALL_DIR%\Ghidra" goto continue2

::
:: Development Environment (Eclipse classes or "gradle jar")
::
set "INSTALL_DIR=%INSTALL_DIR%\..\..\.."
set "CPATH=%INSTALL_DIR%\Ghidra\Framework\Utility\bin\main"
set "LS_CPATH=%INSTALL_DIR%\GhidraBuild\LaunchSupport\bin\main"
if not exist "%LS_CPATH%" (
	set "CPATH=%INSTALL_DIR%\Ghidra\Framework\Utility\build\libs\Utility.jar"
	set "LS_CPATH=%INSTALL_DIR%\GhidraBuild\LaunchSupport\build\libs\LaunchSupport.jar"
)
if not exist "%LS_CPATH%" (
	echo ERROR: Cannot launch from repo because Ghidra has not been compiled with Eclipse or Gradle.
	set ERRORLEVEL=1
	goto exit1
)
set "DEBUG_LOG4J=%INSTALL_DIR%\Ghidra\RuntimeScripts\Common\support\debug.log4j.xml"

:continue2

:: This is to force Java to use the USERPROFILE directory for user.home
if exist "%USERPROFILE%" (
	set VMARG_LIST=%VMARG_LIST% -Duser.home="%USERPROFILE%"
)

:: check for java based upon PATH
set JAVA_CMD=java.exe
java.exe -version >NUL 2>&1
if %ERRORLEVEL% equ 0 goto continue3

:: check for java based upon JAVA_HOME environment variable
if not defined JAVA_HOME goto javaNotFound
set "JAVA_CMD=%JAVA_HOME%\bin\java.exe"
"%JAVA_CMD%" -version >NUL 2>&1
if %ERRORLEVEL% equ 0 goto continue3
echo WARNING: JAVA_HOME environment variable is set to an invalid directory: %JAVA_HOME%

:javaNotFound
echo.
echo ERROR: The 'java' command could not be found in your PATH or with JAVA_HOME.
echo Please refer to the Ghidra Installation Guide's Troubleshooting section.
set ERRORLEVEL=1
goto exit1

:: Use LaunchSupport to locate supported java runtime
:continue3

:: Get the JDK that will be used to launch Ghidra
set LS_JAVA_HOME=
for /f "delims=*" %%i in ('call "%JAVA_CMD%" -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%" %JAVA_TYPE_ARG% -save') do set LS_JAVA_HOME=%%i
if "%LS_JAVA_HOME%" == "" (
	:: No JDK has been setup yet.  Let the user choose one.
	"%JAVA_CMD%" -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%" %JAVA_TYPE_ARG% -ask
	
	:: Now that the user chose one, try again to get the JDK that will be used to launch Ghidra
	for /f "delims=*" %%i in ('call "%JAVA_CMD%" -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%" %JAVA_TYPE_ARG% -save') do set LS_JAVA_HOME=%%i
	if "!LS_JAVA_HOME!" == "" (
		echo.
		echo ERROR: Failed to find a supported JDK.
		echo Please refer to the Ghidra Installation Guide's Troubleshooting section.
		set ERRORLEVEL=1
		goto exit1
	)
)
set "JAVA_CMD=%LS_JAVA_HOME%\bin\java"

:: Get the configurable VM arguments from the launch properties
for /f "delims=*" %%i in ('call "%JAVA_CMD%" -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%" -vmargs') do set VMARG_LIST=!VMARG_LIST! %%i

:: Set Max Heap Size if specified
if not "%MAXMEM%"=="" (
	set VMARG_LIST=%VMARG_LIST% -Xmx%MAXMEM%
)

set BACKGROUND=n
set DEBUG=n
set SUSPEND=n

if "%MODE%"=="debug" (
	set DEBUG=y
)

if "%MODE%"=="debug-suspend" (
	set DEBUG=y
	set SUSPEND=y
)
	
if "%DEBUG%"=="y" (
	if "%DEBUG_ADDRESS%"=="" (
		set DEBUG_ADDRESS=127.0.0.1:18001
	)
		
	set VMARG_LIST=!VMARG_LIST! -Dlog4j.configurationFile="!DEBUG_LOG4J!"	
	set VMARG_LIST=!VMARG_LIST! -agentlib:jdwp=transport=dt_socket,server=y,suspend=!SUSPEND!,address=!DEBUG_ADDRESS!
	goto continue4
)

if "%MODE%"=="fg" (
	goto continue4
)

if "%MODE%"=="bg" (
	set BACKGROUND=y
	goto continue4
)

echo "ERROR: Incorrect launch usage - invalid launch mode: %MODE%"
exit /B 1

:continue4

set CMD_ARGS=%FORCE_JAVA_VERSION% %JAVA_USER_HOME_DIR_OVERRIDE% %VMARG_LIST% -cp "%CPATH%" ghidra.Ghidra %CLASSNAME% %ARGS%

if "%BACKGROUND%"=="y" (
	set JAVA_CMD=!JAVA_CMD!w
	start "%APPNAME%" /I /B "!JAVA_CMD!" %CMD_ARGS%
	
	REM If our process dies immediately, output something so the user knows to run in debug mode.
	REM Otherwise they'll never see any error output from background mode.
	REM NOTE: The below check isn't perfect because they might have other javaw's running, but
	REM without the PID of the thing we launched, it's the best we can do (maybe use WMI?).  
	REM Worst case, they just won't see the error message.
	%SystemRoot%\System32\timeout.exe /NOBREAK 1 > NUL
	%SystemRoot%\System32\tasklist.exe | %SystemRoot%\System32\findstr.exe "javaw" > NUL
	if not "!ERRORLEVEL!"=="0" (
		echo Exited with error.  Run in foreground ^(fg^) mode for more details.
	)
) else (
	"%JAVA_CMD%" %CMD_ARGS%
)

:exit1
if not %ERRORLEVEL% == 0 (
	if "%DOUBLE_CLICKED%"=="y" (
		pause
	)
)

exit /B %ERRORLEVEL%
