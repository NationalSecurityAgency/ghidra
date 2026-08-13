BUILDING A GHIDRA JAR FILE
--------------------------

This file contains directions for building Ghidra into a single jar file and how to use that jar
file to run Ghidra. 

Normally, Ghidra is installed as an entire directory structure that allows
modular inclusion or removal of feature sets and also provides many files that can be extended
or configured. However, there are times when it would be useful to have all or some subset of
Ghidra compressed into a single jar file at the expense of configuration options.  This makes Ghidra
easier to run from the command line for headless operation or to use as a library of reverse 
engineering capabilities for another Java application.

Using the buildGhidraJar scripts, as described below, will build a minimal Ghidra 
jar file that is suitable for running Ghidra or including in the class path for use with
other Java applications (e.g., hadoop).  To have more control over which feature/extension modules
are included in the ghidra.jar file, there is also a Ghidra script that you can customize and run
from within Ghidra (BuildGhidraJarScript).

Use of other non-Java scripting languages such as Python is not supported when running 
from a single Ghidra jar configuration.

To build the default ghidra.jar file run the appropriate buildGhidraJar script from the command
line:

Windows:
	buildGhidraJar.bat [-srczip singleSrcZipFileName]

Linux or Mac:
	buildGhidraJar [-srczip singleSrcZipFileName]
		
The script creates a ghidra.jar file in the current directory. 

If you specify the optional -srczip parameter, a single zip file containing all Ghidra source
will be created that is useful for debugging.  Of course, you must have installed/unzipped the Ghidra
source distribution into your install directory for the srczip option to work.


To run Ghidra using the resulting ghidra.jar file, execute the following from the command line:

GUI mode:

	java -Xmx1024M -jar ghidra.jar -gui
	
Headless Analyzer:

	java -Xmx1024M -jar ghidra.jar <headless-analyzer-args...>
	
To see full headless analyzer usage enter the following without any additional arguments:

	java -Xmx1024M -jar ghidra.jar
	
*The above commands assume that a JDK 8 is installed on your system and is contained
within your execution path.  

**The -Xmx1024M specifies the amount of memory java is allowed to use. The 1024 sets the max
Java VM memory to 1 gigabyte. 

If you want to include more modules than the bare minimum, run Ghidra and then
customize and run the BuildGhidraJarScript from within Ghidra.  The script has commented out
example code indicating how to add additional modules.  If you want everything in your
distribution, uncomment the "addAllModules()" call and then run the script.






