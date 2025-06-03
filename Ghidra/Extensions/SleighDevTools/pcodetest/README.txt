
OVERVIEW
--------

The executable 'build' file in this directory is a python script for
building pcode test binaries. Each pcode test binary is built using
an associated toolchain.

The list of available pcode test binaries is in the file pcode_defs.py.
Each entry in this file indicates the required toolchain, and additional
options needed to build the pcode test.

The defaults.py script should be modified to suit your environment
reflecting the installation location of your toolchains, build artifacts, etc. 

Options and parameters for building individual pcodetests are contained
in the pcode_defs.py script.

USAGE
-----

To see a list of available options, run the build script without
arguments.

./build

It is possible to build everything from scratch with this command:

./build -a

Typically, pcode test binaries are built individually per processor,
such as:

./build -t MIPS16

To see a list of all processor tests, run with the --list options:

./build -l

