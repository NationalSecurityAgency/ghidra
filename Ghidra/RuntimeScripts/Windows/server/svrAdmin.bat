@echo off

:: ***********************************************************
:: ** Arguments (each argument set may be repeated):
:: **   [-add <sid>] [-remove <sid>] [-reset <sid>] [-dn <sid> "<x500_distinguished_name>"] 
:: **   [-admin <sid> "<repository-name>"] [-list] [-migrate "<repository-name>"] [-migrate-all]
:: **
:: **   add - add a new user to the server with the default password 'changeme'
:: **   remove - remove an existing user from the server
:: **   reset - reset an existing user's password to 'changeme'
:: **   dn - set a user's distinguished name for PKI authentication
:: **   admin - set the specified existing user as an admin of the specified repository
:: **   list - list all existing named repositories
:: **   migrate - migrate the specified named repository to an indexed data storage
:: **   migrate-all - migrate all named repositories to index data storage
:: ***********************************************************  

setlocal

:: Sets SCRIPT_DIR to the directory that contains this file
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
set SCRIPT_DIR=%~dp0

:: Uncomment and set the value below as necessary
:: set SCRIPT_DIR=<full Ghidra installation server directory path>

if not exist "%SCRIPT_DIR%" (
    echo Unable to set the Ghidra server script directory.
    echo.
    echo To run Ghidra in this mode you must set the
    echo value of SCRIPT_DIR in this file to be 
    echo the full path containing this batch file
    goto :eof
)

:: Production Environment
set CONFIG=%SCRIPT_DIR%.\server.conf
set GHIDRA_DIR=%SCRIPT_DIR%..\Ghidra
set CPATH=%GHIDRA_DIR%\Features\GhidraServer\lib\GhidraServer.jar;%GHIDRA_DIR%\Framework\FileSystem\lib\FileSystem.jar;%GHIDRA_DIR%\Framework\DB\lib\DB.jar;%GHIDRA_DIR%\Framework\Generic\lib\Generic.jar;%GHIDRA_DIR%\Framework\Utility\lib\Utility.jar;%GHIDRA_DIR%\Framework\Generic\lib\log4j-core-2.8.1.jar;%GHIDRA_DIR%\Framework\Generic\lib\log4j-api-2.8.1.jar
set LS_CPATH=%GHIDRA_DIR%\..\support\LaunchSupport.jar

if exist "%GHIDRA_DIR%" goto continue

:: Development Environment - assumes suitable java in command path
set CONFIG=%SCRIPT_DIR%..\..\Common\server\server.conf
set GHIDRA_DIR=%SCRIPT_DIR%..\..\..
set GHIDRA_BIN_HOME=%GHIDRA_DIR%\..\..\ghidra.bin
set CPATH=%GHIDRA_DIR%\Features\GhidraServer\bin\main;%GHIDRA_DIR%\Framework\FileSystem\bin\main;%GHIDRA_DIR%\Framework\DB\bin\main;%GHIDRA_DIR%\Framework\Generic\bin\main;%GHIDRA_DIR%\Framework\Utility\bin\main;%GHIDRA_BIN_HOME%\ExternalLibraries\libsForRuntime\log4j-core-2.8.1.jar;%GHIDRA_BIN_HOME%\ExternalLibraries\libsForRuntime\log4j-api-2.8.1.jar
set LS_CPATH=%GHIDRA_DIR%\..\GhidraBuild\LaunchSupport\bin\main

:continue

:: Make sure some kind of java is on the path.  It's required to run the LaunchSupport program.
java -version >nul 2>nul
if not %ERRORLEVEL% == 0 (
	echo Java runtime not found.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
	exit /B 1
)

:: Get the java that will be used to launch GhidraServer
set JAVA_HOME=
for /f "delims=*" %%i in ('java -cp "%LS_CPATH%" LaunchSupport "%GHIDRA_DIR%\.." -java_home') do set JAVA_HOME=%%i
if "%JAVA_HOME%" == "" (
	echo Failed to find a supported Java runtime.  Please refer to the Ghidra Installation Guide's Troubleshooting section.
	exit /B 1
)
set JAVA=%JAVA_HOME%\bin\java.exe

set VMARGS=-DUserAdmin.invocation="%0" -DUserAdmin.config="%CONFIG%" -Djava.net.preferIPv4Stack=true

"%JAVA%" %VMARGS% -cp "%CPATH%" ghidra.server.UserAdmin %*
