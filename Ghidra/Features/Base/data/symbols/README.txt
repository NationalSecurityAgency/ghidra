The use of library symbol table information is currently limited to Windows
x86 (32-bit and 64-bit).  Currently, the use of these library symbol files are 
best suited for library names which incorporate an API version (e.g., mfc100.dll)
since the .exports and .ord files will utilize this same name for identification.

When the PE loader detects a library dependency (i.e., DLL) and the library is 
not loaded, the subdirectories win32 or win64 will be searched for a corresponding
.exports or .ord file to provide ordinal-to-symbol name mappings.  User generated
.exports and .ord files may also be stored/read from the user's 'symbols' resource
directory contained within the user's version-specific .ghidra directory (e.g., 
%HOMEPATH%/.ghidra/.ghidra-9.0/symbols/win64).

The .exports files can be generated from a loaded library program and can also 
provide function stack purge and function comment information. The Ghidra script 
'CreateExportFileForDLL' may be used to generate a .exports file for the current 
program which will be stored within the user's 'symbols' resource directory 
mentioned above.

Many library functions are referenced through the use of ordinals and may be 
missing real symbol names.  In such cases it may be desirable to rely on ordinal
to symbol name map .ord files which may be generated with the following command:

  DUMPBIN /EXPORTS <DLL-FILEPATH>
  
The DUMPBIN utility is provided with Microsoft Visual Studio.  The resulting output
should be stored within a .ord file using the DLL name (e.g., mfc100.ord).
