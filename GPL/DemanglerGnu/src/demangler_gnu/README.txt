PURPOSE

This is a readme file to note the changes made to the binutils-2.24 source 
code in order for Ghidra to build its GNU demangler.




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

cplus-dem.c

To this file was added about 400 lines of source code.  Previously, this file contained a 
main method that we used to build our stand alone demangler.   The current version of 
binutils does not have this main method.  Instead, binutils has only a main method in 
cp-demangle.c for building the stand alone demangler.  The c++filt utility is created using 
a main method inside of cxxfilt.c.  We could not build that utility without using the 
more complicated build system mentioned above.  

In order to gain full functionality contained in the c++filt utility, we copied the main 
method from cxxfilt.c and placed it, along with supporting methods, into cplus-dem.c.  This 
allows us to perform a simple build of the stand alone demangler, with less source files 
required.

cp-demangle.c *

This file contains a small, two-line change to send a newline character ('\n') along with 
a flush to the output stream.  Without this change, the program, when called repeatedly from 
Ghidra would eventually hang.  This is due to the nature of how Ghidra reads results in a 
line-oriented fashion.

*This change is no longer used, as we do not use the main method inside of this file, but have
switched to the main method we made and placed into cplus-dem.c.




UPDATING

If we ever wish to update to a newer version of binutils, then we will need to re-copy the files
in this directory and then rebuild the main method we created inside of cplus-dem.c.  That is, 
unless at least one of the following changes happens: 

1) the stand alone demangler in cp-demangle has full c++filt support, or
2) binutils has put the main method back inside cplus-dem.c, or 
3) building a stand alone c++filt is simple enough that we can do it on each platform, or
4) we decide to build the entire binutils suite and use the full c++filt binary. 




SOURCE FILES NEEDED BY OS


*nix / Mac

ansidecl.h
argv.c
cp-demangle.c
cp-demangle.h
cplus-dem.c
demangle.h
dyn-string.c
dyn-string.h
getopt.c
getopt.h
libiberty.h
safe-ctype.c
safe-ctype.h
xexit.c
xstrdup.c

WINDOWS



alloca.c
getopt1.c

