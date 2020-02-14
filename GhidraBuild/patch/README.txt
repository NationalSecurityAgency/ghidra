Into this directory may be added compiled Java class files, either inside of a jar file or 
in a directory structure.   This directory and the contained jar files will be prepended to
the classpath, allowing them to override any existing classes in any module.

The jar files will be sorted by name before being added to the classpath in order to present
predictable class loading between Ghidra runs.  This directory will be prepended on the classpath
before any jar files, given the classes in this directory precedence over the jar files.

The class files in this directory must be in a directory structure that matches their respective
packages.


