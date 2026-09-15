README_createPdbXmlFiles.txt

The createPdbXmlFiles.bat script included in the Ghidra distribution's /support folder can be used
to create *.PDB.XML files from *.PDB files. *.PDB.XML files can be used to load and apply symbols to 
Microsoft-compiled programs in Ghidra when the user is not on a Windows machine.

Before running the createPdbXmlFiles.bat script, you will need to ensure that the runtime libarry 
dependencies of pdb.exe are satisfied on your Windows system.  To do so, please follow the instructions 
in the docs/README_PDB.html file.

Once you have verified that the DIA SDK is installed, use a command window to navigate to the <ghidra
install root>/support folder and run the script with either a single PDB file or a directory that
contains PDB files as its argument. The script will recursively traverse all subdirectories of a given
directory to find PDB files.

For example:

	createPdbXmlFiles.bat C:\Symbols\samplePdb.pdb
	createPdbXmlFiles.bat C:\Symbols

A created .PDB.XML file will be placed in the same location as the corresponding original .PDB file. 


_NOTES_
* There is also a Ghidra GUI-based version of createPdbXmlFiles.bat. It is available from the GUI's
Script Manager (see the "Load PDB File" section of Ghidra Help for more details).  

* The createPdbXmlFiles.bat script may not work when operating on files that are located on a mounted
drive or remote server. For best results, please make sure the PDB files or directories you are using
as the argument to the script are local to the script.
