@echo off

:: ***********************************************************
:: ** Arguments (each -argument option may be repeated):
:: **   [-add <sid>] [-dn <sid> "<x500_distinguished_name>"]
:: **   [-remove <sid>] 
:: **   [-reset <sid>]
:: **   [-admin <sid> "<repository-name>"] 
:: **   [-list] [-users] 
:: **   [-migrate "<repository-name>"] [-migrate-all]
:: **
:: **   add - add a new user to the server with the default password 'changeme'
:: **   dn - set a user's distinguished name for PKI authentication
:: **   remove - remove an existing user from the server
:: **   reset - reset an existing user's password to 'changeme'
:: **   admin - set the specified existing user as an admin of the specified repository
:: **   list - list all existing named repositories
:: **   users - list all users or those associated with each listed repository
:: **   migrate - migrate the specified named repository to an indexed data storage
:: **   migrate-all - migrate all named repositories to index data storage
:: ***********************************************************  

setlocal

:: maximum heap memory may be change if inadequate
set MAXMEM=128M

:: Sets SCRIPT_DIR to the directory that contains this file
::
:: '% ~' dereferences the value in param 0
:: 'd' - drive
:: 'p' - path (without filename)
set SCRIPT_DIR=%~dp0

:: Production Environment
set CONFIG=%SCRIPT_DIR%.\server.conf

if exist "%CONFIG%" goto continue

:: Development Environment
set CONFIG=%SCRIPT_DIR%..\..\Common\server\server.conf

:continue

set VMARGS=-DUserAdmin.invocation="%0" -DUserAdmin.config="%CONFIG%"

call "%~dp0\..\support\launch.bat" fg svrAdmin "%MAXMEM%" "%VMARGS%" ghidra.server.ServerAdmin %*
