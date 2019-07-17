:: Script that takes either a single .pdb file or a directory
:: that contains .pdb files (search for files is recursive).
::
:: Parses each .pdb file and creates a corresponding .pdb.xml
:: file in the same location as the original file.
::
:: The .pdb.xml files can be used to apply debugging information
:: when running Ghidra on non-Windows systems.

@echo off
setlocal

REM Get parent of current folder
set SCRIPT_DIR=%~dp0

set GHIDRA_DIR=%SCRIPT_DIR%..\Ghidra
set OS_DIR=os

REM Production Environment
if exist "%GHIDRA_DIR%" goto continue

REM Development Environment
set GHIDRA_DIR=%SCRIPT_DIR%..\..\..
set OS_DIR=build\os

:continue

REM create absolute path
for /f %%i in ("%GHIDRA_DIR%") do set GHIDRA_DIR=%%~fi

REM Determine if 64-bit or 32-bit
if exist "%PROGRAMFILES(X86)%" (
	set OS_TYPE=win64
) else (
	set OS_TYPE=win32
)

set PDB_EXE=%GHIDRA_DIR%\Features\PDB\%OS_DIR%\%OS_TYPE%\pdb.exe

if not exist "%PDB_EXE%" (
	echo "%PDB_EXE% not found"
	Exit /B 1
)

if "%~1" == "" (
	echo "Usage: createPdbXmlFiles.bat <path to .pdb file|path to directory of .pdb files>"
	Exit /B 1
)

set arg1="%~1"

set /a count=0

REM Recursively traverse through the given directory
REM Create the .pdb.xml file in the same directory as the .pdb file
for /f "tokens=* delims=" %%a in ('dir %arg1% /s /b') do (

	REM Check if we are dealing with a file
	if not exist %%a\ (
	
		REM Run pdb.exe on found .pdb file	
		if %%~xa equ .pdb (

			setlocal enableDelayedExpansion
			(
				echo "Processing file: %%a"
				START /B /WAIT "" "%PDB_EXE%" %%a > "%%a.xml"

				REM Exit if executable returned non-zero error code (signifies that there is a problem).
				if !errorlevel! neq 0 (
					REM Delete empty XML file that was just created
					del "%%a.xml"

					if !count! geq 1 (
						echo "Error detected. Created !count! .pdb.xml file(s) before exiting"
					) else (
						echo Error detected. Exiting...
					)

					Exit /B 1
				)
			)

			set /a count+=1
		)
	)
)

echo Created %count% .pdb.xml file(s).
