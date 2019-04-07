:: Ghidra Filesystem Conversion launch

@echo off
setlocal

:: maximum heap memory may be change if inadequate
set MAXMEM=128M

call "%~dp0launch.bat" fg ConvertStorage "%MAXMEM%" "" ghidra.framework.data.ConvertFileSystem %*
