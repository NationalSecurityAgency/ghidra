@echo off
goto continue

:showUsage
echo Usage: %0 ^<mode^> ^<name^> ^<max-memory^> "<vmarg-list>" ^<app-classname^> ^<app-args^>... 
echo    ^<mode^>: fg    run as foreground process in current shell
echo              bg    run as background process in new shell
echo              debug run as foreground process in current shell in debug mode ^(suspend=n^)
echo              debug-suspend   run as foreground process in current shell in debug mode ^(suspend=y^)
echo              NOTE: for all debug modes environment variable DEBUG_ADDRESS may be set to 
echo                    override default debug address of 127.0.0.1:18001
echo    ^<name^>: application name used for naming console window
echo    ^<max-memory^>: maximum memory heap size in MB ^(e.g., 768M or 2G^).  Use "" if default should be used.
echo                  This will generally be upto 1/4 of the physical memory available to the OS.  On 
echo                  some systems the default could be much less (particularly for 32-bit OS).
echo    ^<vmarg-list^>: pass-thru args ^(e.g.,  "-Xmx512M -Dmyvar=1 -DanotherVar=2"^) - use
echo                empty "" if vmargs not needed
echo    ^<app-classname^>: application classname ^(e.g., ghidra.GhidraRun ^)
echo    ^<app-args^>...: arguments to be passed to the application
echo.
echo    Example: 
echo       %0 debug Ghidra 768M "" ghidra.GhidraRun
exit /B 1

:continue

:: Delay the expansion of our loop items below since the value is being updated as the loop works
setlocal enabledelayedexpansion

:: See if we were doubled clicked or run from a command prompt
set DOUBLE_CLICKED=n
for /f "tokens=2" %%# in ("%cmdcmdline%") do if /i "%%#" equ "/c" set DOUBLE_CLICKED=y

:: Sets SUPPORT_DIR to the directory that contains this file (ends with '\')
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
set SUPPORT_DIR=%~dp0

::
:: Parse arguments
::
set VMARG_LIST=
set ARGS=
set INDEX=0
for %%A in (%*) do (
	set /A INDEX=!INDEX!+1
	if "!INDEX!"=="1" ( set MODE=%%A
	) else if "!INDEX!"=="2" ( set APPNAME=%%A
	) else if "!INDEX!"=="3" ( set MAXMEM=%%~A
	) else if "!INDEX!"=="4" ( if not "%%~A"=="" set VMARG_LIST=%%~A
	) else if "!INDEX!"=="5" ( set CLASSNAME=%%~A
	) else set ARGS=!ARGS! %%A
)

if %INDEX% geq 5 goto continue1
echo Incorrect launch usage - missing argument^(s^)
goto showUsage

:continue1

::
:: Production Environment
::
set INSTALL_DIR=%SUPPORT_DIR%..\
set CPATH=%INSTALL_DIR%Ghidra\Framework\Utility\lib\Utility.jar
set LS_CPATH=%SUPPORT_DIR%LaunchSupport.jar
set DEBUG_LOG4J=%SUPPORT_DIR%debug.log4j.xml

if exist "%INSTALL_DIR%Ghidra" goto continue2

::
:: Development Environment
::
set INSTALL_DIR=%INSTALL_DIR%..\..\..\
set CPATH=%INSTALL_DIR%Ghidra\Framework\Utility\bin\main
set LS_CPATH=%INSTALL_DIR%GhidraBuild\LaunchSupport\bin\main
set DEBUG_LOG4J=%INSTALL_DIR%Ghidra\RuntimeScripts\Common\support\debug.log4j.xml

:continue2

:: This is to force Java to use the USERPROFILE directory for user.home
if exist "%USERPROFILE%" (
	set VMARG_LIST=%VMARG_LIST% -Duser.home="%USERPROFILE%"
)

:: Make sure some kind of java is on the path.  It's required to run the LaunchSupport program.
java -version >nul 2>nul
if not %ERRORLEVEL% == 0 (
	echo Java runtime not found.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
	goto exit1
)

:: Get the JDK that will be used to launch Ghidra
set JAVA_HOME=
for /f "delims=*" %%i in ('java -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%\" -jdk_home -save') do set JAVA_HOME=%%i
if "%JAVA_HOME%" == "" (
	:: No JDK has been setup yet.  Let the user choose one.
	java -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%\" -jdk_home -ask
	
	:: Now that the user chose one, try again to get the JDK that will be used to launch Ghidra
	for /f "delims=*" %%i in ('java -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%\" -jdk_home -save') do set JAVA_HOME=%%i
	if "!JAVA_HOME!" == "" (
		echo.
		echo Failed to find a supported JDK.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
		set ERRORLEVEL=1
		goto exit1
	)
)
set JAVA_CMD=%JAVA_HOME%\bin\java

:: Get the configurable VM arguments from the launch properties
for /f "delims=*" %%i in ('java -cp "%LS_CPATH%" LaunchSupport "%INSTALL_DIR%\" -vmargs') do set VMARG_LIST=%VMARG_LIST% %%i

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
		
	set VMARG_LIST=!VMARG_LIST! -Xdebug
	set VMARG_LIST=!VMARG_LIST! -Xnoagent
	set VMARG_LIST=!VMARG_LIST! -Djava.compiler=NONE
	set VMARG_LIST=!VMARG_LIST! -Dlog4j.configuration="!DEBUG_LOG4J!"
	set VMARG_LIST=!VMARG_LIST! -Xrunjdwp:transport=dt_socket,server=y,suspend=!SUSPEND!,address=!DEBUG_ADDRESS!
	goto continue3
)

if "%MODE%"=="fg" (
	goto continue3
)

if "%MODE%"=="bg" (
	set BACKGROUND=y
	goto continue3
)

echo "Incorrect launch usage - invalid launch mode: %MODE%"
exit /B 1

:continue3

set CMD_ARGS=%FORCE_JAVA_VERSION% %JAVA_USER_HOME_DIR_OVERRIDE% %VMARG_LIST% -cp "%CPATH%" ghidra.GhidraLauncher %CLASSNAME% %ARGS%

if "%BACKGROUND%"=="y" (
	set JAVA_CMD=!JAVA_CMD!w
	start "%APPNAME%" /I /B "!JAVA_CMD!" %CMD_ARGS%
	
	REM If our process dies immediately, output something so the user knows to run in debug mode.
	REM Otherwise they'll never see any error output from background mode.
	REM NOTE: The below check isn't perfect because they might have other javaw's running, but
	REM without the PID of the thing we launched, it's the best we can do (maybe use WMI?).  
	REM Worst case, they just won't see the error message.
	timeout /NOBREAK 1 > NUL
	tasklist | find "javaw" > NUL
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
