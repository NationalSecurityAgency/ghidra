# Ghidra Analysis from the Command Line 

For the remaining exercises, we need to populate our BSim database with a number of binaries. 
We'd like a consistent set of binaries for the tutorial, but we don't want to clutter the Ghidra distribution with dozens of additional executables.
Fortunately, the BSim plugin includes a script for building the PostgreSQL backend, and that build process creates hundreds of object files.
So we can just build PostgreSQL and harvest the object files we need.

**Note**: For the tutorial, we continue to use the H2 BSim backend. 
We do not run any PostgreSQL code, we simply analyze some files produced when building PostgreSQL.

Note that these files must be built on a machine running Linux.
Windows users can build these files in a Linux virtual machine.

To build the files, execute the following commands in a shell: [^1] 

[^1]: You may need to install additional packages and/or change some build options in order for PostgreSQL to build successfully. The error messages are generally informative.  See the comments in ``make-postgres.sh``.

```bash
cd <ghidra_install_dir>/Features/BSim
export CFLAGS="-O2 -g"
./make-postgres.sh
mkdir ~/postgres_object_files
cd build
find . -name p*o -size +100000c -size -700000c -exec cp {} ~/postgres_object_files/ \;
cd os/linux_x86_64/postgresql/bin
strip -s postgres
```

To continue on Windows, transfer the ``~/postgres_object_files`` directory and the stripped ``postgres`` executable to your Windows machine.

## Importing and Analyzing the Exercise Files

Now that we have the executables, we can analyze them with the headless analyzer[^2].
The headless analyzer is distinct from BSim, but using it is the only feasible way to analyze substantial numbers of binaries.

[^2]: The headless analyzer has its own documentation: ``<ghidra_install_dir>/support/analyzeHeadlessREADME.html``.

To analyze the files in Linux, execute the following commands in a shell.

```bash
cd <ghidra_install_dir>/support
./analyzeHeadless <ghidra_project_dir> postgres_object_files -import ~/postgres_object_files/*
```
(On windows, use ``analyzeHeadless.bat`` and adjust paths accordingly.)

This will create a local Ghidra project called ``postgres_object_files`` in the directory ``<ghidra_project_dir>``. 


Next Section: [BSim from the Command Line](BSimTutorial_BSim_Command_Line.md)

