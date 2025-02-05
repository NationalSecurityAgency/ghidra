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

# What's New in Ghidra 11.3
This release includes new features, enhancements, performance improvements, quite a few bug fixes,
and many pull-request contributions. Thanks to all those who have contributed their time, thoughts,
and code. The Ghidra user community thanks you too!
	
### The not-so-fine print: Please Read!
Ghidra 11.3 is fully backward compatible with project data from previous releases. However, programs
and data type archives which are created or modified in 11.3 will not be usable by an earlier Ghidra
version.

**IMPORTANT:** Ghidra 11.3 requires at minimum JDK 21 to run.

**IMPORTANT:** To use the Debugger or do a full source distribution build, you will need Python3
(3.9 to 3.13 supported) installed on your system.

**NOTE:** There have been reports of certain features causing the XWindows server to crash. A fix
for `CVE-2024-31083` in X.org software in April 2024 introduced a regression, which has been fixed
in xwayland 23.2.6 and xorg-server 21.1.13.  If you experience any crashing of Ghidra, most likely
causing a full logout, check if your xorg-server has been updated to at least the noted version.

**NOTE:** Each build distribution will include native components (e.g., decompiler) for at least one
platform (e.g., Windows x86-64). If you have another platform that is not included in the build
distribution, you can build native components for your platform directly from the distribution.
See the *Installation Guide* for additional information. Users running with older shared libraries
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

## PyGhidra
The PyGhidra Python library, originally developed by the Department of Defense Cyber Crime Center 
(DC3) under the name *Pyhidra*, is a Python library that provides direct access to the Ghidra API 
within a native CPython 3 interpreter using JPype. PyGhidra contains some conveniences for setting 
up analysis on a given sample and running a Ghidra script locally. It also contains a Ghidra plugin 
to allow the use of CPython 3 from the Ghidra GUI.

To launch Ghidra in PyGhidra mode, run `./support/pyghidra` (or `support\pyghidra.bat`). See the
*"PyGhidra Mode"* section of the *Installation Guide* and `Ghidra/Features/PyGhidra/README.html`
for more information.

## Visual Studio Code
Ghidra 11.2 introduced a `VSCodeProjectScript.java` GhidraScript to assist in setting up Visual Studio Code
project folders for Ghidra module development and debugging. This GhidraScript has been replaced in 
Ghidra 11.3 by 2 new actions, accessible from a *CodeBrowser* tool:
+ *Tools -> Create VSCode Module Project...*
+ "*Edit Script with Visual Studio Code*" button in the Script Manager

The "*Create VSCode Module Project...*" action provides the same capability as the old
`VSCodeProjectScript.java` GhidraScript, creating a Visual Studio Code project folder that contains a
skeleton module which can be used to build a variety of different Ghidra extension points
(Plugins, Analyzers, Loaders, etc). Launchers are also provided to run and debug the module in
Ghidra, as well as a Gradle task to export the module as a distributable Ghidra extension zip file.

The "*Edit Script with Visual Studio Code*" button in the Script Manager enables quick editing and
debugging of the selected script in a Visual Studio Code workspace that is automatically created
behind the scenes in Ghidra's user settings directory. This provides a much snappier and modern
alternative to Eclipse, while maintaining all of the core fuctionality you would expect from an IDE
(auto complete, hover, navigation, etc).

Ghidra will do its best to automatically locate your Visual Studio Code installation, but if cannot
find it, it can be set via the Front-End GUI at *Edit -> Tool Options -> Visual Studio Code
Integration*.

## Debugger
The old "IN-VM" and "GADP" launchers and connectors have been removed, as their replacement
TraceRmi-based implementations have been satisfactorily completed. On that same note, the entire API
and supporting code base for IN-VM and GADP connectors have been removed.

We've begun to explore more kernel-level debugging. Our lldb connector can now debug the macOS 
kernel, and our dbgeng connector can now debug a Windows kernel running in a VM via eXDI.

## Emulator
We have introduced a new accelerated p-code emulator that uses Jit-in-Time translation (JIT). 
This is *not* currently integrated in the UI but is available for scripting and plugin developers. 
Its implementation is named `JitPcodeEmulator`, and it's a near drop-in replacement for `PcodeEmulator`. 
See its javadoc for usage and implementation details. The JIT emulator is very new, so there may 
still be many bugs.

## Source File Information
Source file and line information can now be added to Ghidra using a Program's SourceFileManager. 
The DWARF, PDB, and Go analyzers now record this information by default. Source information can also
be added programmatically; see the example scripts in the *SourceMapping* script category. 
Source information can be viewed in the *"Source Map"* Listing Field or the `SourceFilesTablePlugin`, 
which is accessible from the Code Browser via *Window -> Source Files and Transforms*.

The *"View Source..."* Listing action, enabled on addresses with source file information, opens a 
source file at the correct line in either Eclipse or Visual Studio Code (there is a *"Source Files 
and Transforms"* tool option to determine the viewer). The SourceFilesTablePlugin can be used to 
modify the source file paths stored in the SourceFileManager before sending them to Eclipse or 
Visual Studio Code.

## Function Graph
The Function Graph has had a number of improvements:
+ Added new *"Flow Chart"* layouts
+ Position of the satellite view can be configured
+ Ctrl-Space toggles between the Listing and the Function Graph (starting fully zoomed in vs. fully
  zoomed out is controlled by a Function Graph option)

## String Translation and Text Search
+ String translation has an additional translator available using the LibreTranslate service.
  The LibreTranslate project (currently hosted at libretranslate.com) is an independent project
  that provides an open source translation package that can be self-hosted, meaning you can translate
  strings without sending them to a second party to translate, using an existing LibreTranslate server.
  For more information search for LibreTranslate in the online Ghidra help pages.
  **NOTE:** The LibreTranslate plugin is not enabled by default, and is added in the 
  *File -> Configure* menu.

+ The ability to search the text of all decompiled functions has been added.  Decompilation during
  search occurs on the fly, so the latest decompilation results of all functions are used for the
  search.  The search can take some time depending on the number and size of functions in your binary.
  The new action can be found at *Search -> Decompiled Text...*.

## Processors
+ The x86 EVEX instruction write and read masking has been implemented for all AVX-512 instructions.
  The handling of the mask is necessary as semantics are added for individual AVX-512 instructions.
+ TI_MSP430 decompilation has been improved through numerous changes to the processor's compiler
  specifications file.
+ Corrected ARM VFPv2 instructions which were not disassembling correctly.

## Other Improvements 
+ Much of Ghidra's standalone documentation has been modernized to the Markdown format. Generated 
  HTML versions are provided alongside the Markdown files for convenience. Converting all relevant
  documents to Markdown remains an ongoing process.  **NOTE:** There are no plans to convert the
  internal Ghidra help system to Markdown, as the Java Help library does not support it.
+ Libraries can now be loaded into an already-imported program with the *File -> Load Libraries...*
  action.
+ The CParser macro pre-processing will now halt on *"#error"* directives.  This change had a ripple
  effect and uncovered a myriad of bugs which have been addressed.  In addition, the interim parsing
  output has been improved to allow easier diagnosis when problems in parsing occur due to incorrect
  define values or other header file issues.
+ Finally, a new `CreateUEFIGDTArchivesScript.java` parsing script has been added to parse UEFI header files
  available from `github.com/tianocore/edk2`.  Using a script vice released pre-parsed GDT files allows the
  end user to parse the correct version with a configuration fitting their needs.

## Additional Bug Fixes and Enhancements
Numerous other new features, improvements, and bug fixes are fully listed in the 
[Change History](ChangeHistory.html) file.
