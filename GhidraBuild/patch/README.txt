This directory exits so that Ghidra releases can be patched, or overridden. 
Classes or jar files placed in this directory will found and loaded 
*before* the classes that exist in the release jar files. One exception 
is that classes in the Utility module can not be patched in this way.

The jar files will be sorted by name before being prepended to the classpath 
in order to have predictable class loading between Ghidra runs.  This patch 
directory will be the very first patch entry on the classpath such that any 
individual classes will be found before classes in any of the patch jar files.

The class files in this directory must be in the standard java package 
directory structure.
