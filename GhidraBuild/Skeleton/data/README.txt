The "data" directory is intended to hold data files that will be used by this module and will
not end up in the .jar file, but will be present in the zip or tar file.  Typically, data
files are placed here rather than in the resources directory if the user may need to edit them.

An optional data/languages directory can exist for the purpose of containing various Sleigh language
specification files and importer opinion files.  

The data/build.xml is used for building the contents of the data/languages directory.

The skel language definition has been commented-out within the skel.ldefs file so that the 
skeleton language does not show-up within Ghidra.

See the Sleigh language documentation (docs/languages/sleigh.htm or sleigh.pdf) for details
on Sleigh language specification syntax.
 
