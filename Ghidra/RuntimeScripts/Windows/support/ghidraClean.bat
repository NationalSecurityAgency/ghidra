:: Ghidra-Clean
:: An interactive utility to discover and delete artifacts that Ghidra lays down on the filesystem.

@echo off
setlocal

set VMARG_LIST=-Djava.awt.headless=true

call "%~dp0launch.bat" fg jdk Ghidra-Clean "" "" utility.application.AppCleaner Ghidra