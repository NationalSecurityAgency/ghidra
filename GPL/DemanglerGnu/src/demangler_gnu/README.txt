PURPOSE

This is a readme file to note the changes made to the binutils-2.33.1 source 
code in to build its GNU demangler.  The files in this directory are used to create a demangling
utility during the full build process. 




COPIED SOURCE CODE / BUILDING RESTRICTIONS

Most of the files used to build the Ghidra GNU demangler are copied from binutils and have
not been changed.  Further, the files in this directory are a small subset of the files used to
build the binutils suite.  By copying specific files we are able to use Make and Visual Studio
to build a stand alone demangler without having to perform the more complicated build needed
to build binutils.  Specifically, we do not have to run the configure utility that is 
provided by binutils.   This is critical, as we are using Visual Studio to build on Windows, 
which does not have the configure utility support.   If we ever wished to build the entire 
binutils suite on Windows, then we would most likely need to use a GNU environment made for
Windows, such as MinGW.




CHANGES TO BINUTILS SOURCE

cp-demangle.c 

This file contains a small, one-line change to flush to the standard output stream.  Without 
this change, the program, when called repeatedly from Java would hang as it attempts to read
characters that are buffered on the native side.




UPDATING

If we ever wish to update to a newer version of binutils, then we will need to re-copy the files
in this directory.  That is, unless at least one of the following changes happens: 

1) building a stand alone c++filt is simple enough that we can do it on each platform, or
2) we decide to build the entire binutils suite and use the full c++filt binary. 




SOURCE FILES 

binutils/libiberty/alloca.c
binutils/libiberty/argv.c
binutils/libiberty/cp-demangle.c
binutils/libiberty/cplus-dem.c
binutils/libiberty/d-demangle.c
binutils/libiberty/dyn-string.c
binutils/libiberty/getopt.c
binutils/libiberty/getopt1.c
binutils/libiberty/rust-demangle.c
binutils/libiberty/safe-ctype.c
binutils/libiberty/xexit.c
binutils/libiberty/xstrdup.c
binutils/include/ansidecl.h
binutils/libiberty/cp-demangle.h
binutils/include/demangle.h
binutils/include/dyn-string.h
binutils/include/getopt.h
binutils/include/libiberty.h
binutils/libiberty/rust-demangle.h
binutils/include/safe-ctype.h


This file is created to add minor missing dependencies.

missing.c




LICENSE 

The files listed above are licensed by using the file header or the COPYING or COPYING.LIB file
listed in the original source directory of binutils.  
