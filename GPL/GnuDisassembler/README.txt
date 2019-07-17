The GnuDisassembler extension module must be built using gradle prior to its' use within Ghidra.

This module provides the ability to leverage the binutils disassembler capabilities
for various processors as a means of verifying Sleigh disassembler output syntax.

To build this extension for Linux or Mac OS X:

	1. If building for an installation of Ghidra, copy the appropriate source distribution of 
	   binutils into this module's root directory.  If building within a git clone of the full
	   Ghidra source, copy binutils source distribution file into the ghidra.bin/GPL/GnuDisassembler 
	   directory.
	   
	   The supported version and archive format is identified within the build.gradle file.
	   If a different binutils distribution is used the build.gradle and/or buildGdis.gradle
	   may require modification.
	   
	2. Run gradle from the module's root directory (see top of build.gradle file for
	   specific instructions). 

This resulting gdis executable will be located in build/os/<platform>.
