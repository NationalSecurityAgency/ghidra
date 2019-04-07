@echo off
setlocal

rem Find the script directory
rem %~dsp0 is location of current script under NT
set _REALPATH=%~dp0

call "%_REALPATH%\ghidraSvr" uninstall

pause

