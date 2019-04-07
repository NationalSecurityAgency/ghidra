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

if "%~1" == "" (
	echo "Usage: createPdbXmlFiles.bat <path to .pdb file|path to directory of .pdb files>"
	Exit /B 0
)

REM Get parent of current folder
for %%A in (%~dp0\.) do set ghidraPath=%%~dpA

REM Production Environment
if exist "%ghidraPath%Ghidra" goto continue

REM Development Environment
set ghidraPath="%ghidraPath%..\..\..\..\ghidra.bin\"

:continue

set arg1="%~1"

REM Determine if 64-bit or 32-bit
if exist "%PROGRAMFILES(X86)%" (
	set osType=win64
) else (
	set osType=win32
)

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
				START /B /WAIT "" "%ghidraPath%Ghidra\Features\PDB\os\%ostype%\pdb.exe" %%a > "%%a.xml"

				REM Exit if executable returned non-zero error code (signifies that there is a problem).
				if !errorlevel! neq 0 (
					REM Delete empty XML file that was just created
					del "%%a.xml"

					if !count! geq 1 (
						echo "Error detected. Created !count! .pdb.xml file(s) before exiting"
					) else (
						echo Error detected. Exiting...
					)

					Exit /B 0
				)
			)

			set /a count+=1
		)
	)
)

echo Created %count% .pdb.xml file(s).
