# Ghidra: NSA Reverse Engineering Software
Ghidra is a software reverse engineering (SRE) framework developed by NSA's Research Directorate.
This framework includes a suite of full-featured, high-end software analysis tools that enable users
to analyze compiled code on a variety of platforms including Windows, MacOS, and Linux. Capabilities
include disassembly, assembly, decompilation, debugging, emulation, graphing, and scripting, along
with hundreds of other features.  Ghidra supports a wide variety of processor instruction sets and
executable formats and can be run in both user-interactive and automated modes.  Users may also
develop their own Ghidra plug-in components and/or scripts using the exposed API.  In addition there
are numerous ways to extend Ghidra such as new processors, loaders/exporters, automated analyzers,
and new visualizations.

In support of NSA's Cybersecurity mission, Ghidra was built to solve scaling and teaming problems on
complex SRE efforts and to provide a customizable and extensible SRE research platform.  NSA has
applied Ghidra SRE capabilities to a variety of problems that involve analyzing malicious code and
generating deep insights for NSA analysts who seek a better understanding of potential
vulnerabilities in networks and systems.

# What's New in Ghidra 11.4
This release includes new features, enhancements, performance improvements, quite a few bug fixes,
and many pull-request contributions. Thanks to all those who have contributed their time, thoughts,
and code. The Ghidra user community thanks you too!
	
### The not-so-fine print: Please Read!
Ghidra 11.4 is fully backward compatible with project data from previous releases. However, programs
and data type archives which are created or modified in 11.4 will not be usable by an earlier Ghidra
version.

**IMPORTANT:** Ghidra 11.4 requires at minimum JDK 21 to run.

**IMPORTANT:** To use the Debugger or do a full source distribution build, you will need Python3
(3.9 to 3.13 supported) installed on your system.

**NOTE:** There have been reports of certain features causing the XWindows server to crash. A fix
for `CVE-2024-31083` in X.org software in April 2024 introduced a regression, which has been fixed
in xwayland 23.2.6 and xorg-server 21.1.13.  If you experience any crashing of Ghidra, most likely
causing a full logout, check if your xorg-server has been updated to at least the noted version.

**NOTE:** Each build distribution will include native components (e.g., decompiler) for at least one
platform (e.g., Windows x86-64). If you have another platform that is not included in the build
distribution, you can build native components for your platform directly from the distribution.
See the *Getting Started* document for additional information. Users running with older shared libraries
and operating systems (e.g., CentOS 7.x) may also run into compatibility errors when launching 
native executables such as the Decompiler and GNU Demangler which may necessitate a rebuild of 
native components.

**NOTE:** Ghidra Server: The Ghidra 11.x server is compatible with Ghidra 9.2 and later Ghidra
clients. Ghidra 11.x clients are compatible with all 10.x and 9.x servers.  Although, due to
potential Java version differences, it is recommended that Ghidra Server installations older than 
10.2 be upgraded.  Those using 10.2 and newer should not need a server upgrade.
	
**NOTE:** Programs imported with a Ghidra beta version or code built directly from source code
outside of a release tag may not be compatible, and may have flaws that won't be corrected by using
this new release.  Any programs analyzed from a beta or other local master source build should be
considered experimental and re-imported and analyzed with a release version.
	
Programs imported with previous release versions should upgrade correctly through various automatic
upgrade mechanisms.  However, there may be improvements or bug fixes in the import and analysis 
process that will provide better results than prior Ghidra versions.  You might consider comparing a
fresh import of any program you will continue to reverse engineer to see if the latest Ghidra 
provides better results.


## Search

A new "Search and Replace" feature allows searching for string patterns in a wide variety
of Ghidra elements and replacing that text with a different text sequence. Using this feature, many different
Ghidra elements can be renamed all at once including labels, functions, name-spaces, parameters, data-types,
field names, and enum values. This feature also supports regular expressions (including capture groups).
After initiating a search and replace, a results table is displayed with a list of items that match the
search. From this table, the replace actions can be applied in bulk or individually, one item at a time
as they are reviewed.

## Taint Engine Support

Extended support for using taint engines, particularly CTADL (https://github.com/sandialabs/ctadl)
and AngryGhidra (https://github.com/Nalen98/AngryGhidra), from the decompiler. Allows users to mark
pcode varnodes as sources and sinks, displaying paths from sources to sinks as both address selections
in the disassembly and token selections in the decompiler.

## Dockerized Ghidra

A new capability to build a docker image that demonstrates Ghidra's various entrypoint executions for `headless`,
`ghidra-server`, `bsim-server`, `bsim`, `pyghidra`, and `gui` within the docker container has been included. The Docker
image can be used as is, or can be tailored to your workflow needs.   Configuration such as the base
image (linux distro), additional packages, and more is possible using Docker.

See the `docker/README.md` for information about building a docker image for Ghidra and running within the Ghidra container. 


## Binary Formats

+ New loaders for the a.out and OMF-51 binary file formats.
+ Support for Mach-O "re-exports".
+ New ability to load Mach-O binaries directly from a Universal Binary without needing to open the File System Browser.
+ DWARF will now load external debug files during analysis as is done for PDB files.

## Debugger

There have been numerous improvements, extensions for new targets, better launching and configuration, and bug fixes to the debugger.

## Analysis Speed

Constant and Stack analysis time has been greatly decreased through algorithm improvements and better threading.  There has been additional
work to loosen locking of the program database where possible.  By locking only when necessary, multiple threads can better analyze the program
and interaction with the GUI during analysis should be more responsive.

## Golang

Golang binary analysis analysis has been improved.
+ Analysis has been improved to model closures, interface methods, and generic functions more accurately.
+ Function signatures for core golang library functions are automatically applied.
+ Decompilation results are improved by filtering some verbose golang garbage collection function logic.
+ Addressed finding the Golang bootstrap information in stripped PE binaries.

## BSim

PostgreSQL for BSim has been updated to version 15.13 and the JDBC driver to 42.7.6.  This resolves issues with building PostgreSQL
server on newer releases of Linux and compiler toolchains which compile with -std=c23 option by default.  In addition,
building of PostgreSQL for linux_arm_64 and mac_arm_64 based platforms is supported.

+ BSim is now installed in the default Codebrowser tool.
+ Function names now update in BSim search results overview if the name is changed elsewhere in Ghidra.

## Processors

+ Enhanced support for the x86 AVX-512 processor extension with additional instruction support - including the BF16, FP16 and VNNI extensions.
+ Implemented many AARCH64 Neon instruction semantics to improve decompilation.
+ Upgraded pcodetest framework scripts to python3 and improved command-line options.

## Other Improvements
 + Many calling conventions for various processors/compilers have been improved using the more flexible decompiler rules 
 when the data types for parameters and return values are known.
 + Upgraded many 3rd party dependencies to address potential bugs and CVE's, including jars for Bouncy Castle,
 Apache Commons Compress, Apache Commons Lang3, Apache Commons IO, protobuf, and JUnit.

## Additional Bug Fixes and Enhancements
Numerous other new features, improvements, and bug fixes are fully listed in the 
[Change History](ChangeHistory.md) file.
