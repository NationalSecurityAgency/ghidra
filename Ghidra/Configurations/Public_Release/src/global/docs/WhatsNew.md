# Ghidra: NSA Reverse Engineering Software
Ghidra is a software reverse engineering (SRE) framework developed by NSA's Research Directorate.
This framework includes a suite of full-featured, high-end software analysis tools that enable users
to analyze compiled code on a variety of platforms including Windows, MacOS, and Linux. Capabilities
include disassembly, assembly, decompilation, debugging, emulation, graphing, and scripting, along
with hundreds of other features.  Ghidra supports a wide variety of processor instruction sets and
executable formats and can be run in both user-interactive and automated modes.  Users may also
develop their own Ghidra plug-in components and/or scripts using the exposed API.  In addition, there
are numerous ways to extend Ghidra such as new processors, loaders/exporters, automated analyzers,
and new visualizations.

In support of NSA's Cybersecurity mission, Ghidra was built to solve scaling and teaming problems on
complex SRE efforts and to provide a customizable and extensible SRE research platform.  NSA has
applied Ghidra SRE capabilities to a variety of problems that involve analyzing malicious code and
generating deep insights for NSA analysts who seek a better understanding of potential
vulnerabilities in networks and systems.

# What's New in Ghidra 12.0
This release includes new features, enhancements, performance improvements, quite a few bug fixes,
and many pull-request contributions. Thanks to all those who have contributed their time, thoughts,
and code. The Ghidra user community thanks you too!
	
### The not-so-fine print: Please Read!
Ghidra 12.0 is fully backward compatible with project data from previous releases. However, programs
and data type archives which are created or modified in 12.0 will not be usable by an earlier Ghidra
version.

**IMPORTANT:** Ghidra 12.0 requires, at minimum, JDK 21 to run.

**IMPORTANT:** To use the Debugger or do a full source distribution build, you will need Python3
(3.9 to 3.13 supported) installed on your system.

**NOTE:** There have been reports of certain features causing the XWindows server to crash. A fix
for `CVE-2024-31083` in X.org software in April 2024 introduced a regression, which has been fixed
in xwayland 23.2.6 and xorg-server 21.1.13.  If you experience any crashing of Ghidra, most likely
causing a full logout, check if your xorg-server has been updated to at least the noted version.

**NOTE:** Each build distribution will include native components (e.g., Decompiler) for at least one
platform (e.g., Windows x86-64). If you have another platform that is not included in the build
distribution, you can build native components for your platform directly from the distribution.
See the *Getting Started* document for additional information. Users running with older shared 
libraries and operating systems (e.g., CentOS 7.x) may also run into compatibility errors when 
launching native executables such as the Decompiler and GNU Demangler which may necessitate a 
rebuild of native components.

**NOTE:** Ghidra Server: The Ghidra 12.0 server is compatible with Ghidra 11.3.2 and later Ghidra
clients, although the presence of any newer link-files within a repository may not be handled properly
by client versions prior to 12.0 which lack support for the new storage format.  Ghidra 12.0 clients
that introduce new link-files into a project will not be able to add such files into version 
control if connected to older Ghidra Server versions.

**NOTE:** Ghidra Server: Due to potential Java version differences, it is 
recommended that Ghidra Server installations older than 10.2 be upgraded. Those using 10.2 and newer
should not need a server upgrade unless they need to work with link-files within a shared repository.
	
**NOTE:** Programs imported with a Ghidra beta version or code built directly from source code
outside of a release tag may not be compatible, and may have flaws that won't be corrected by using
this new release.  Any programs analyzed from a beta or other local master source build should be
considered experimental and re-imported and analyzed with a release version.
	
Programs imported with previous release versions should upgrade correctly through various automatic
upgrade mechanisms.  However, there may be improvements or bug fixes in the import and analysis 
process that will provide better results than prior Ghidra versions.  You might consider comparing a
fresh import of any program you will continue to reverse engineer to see if the latest Ghidra 
provides better results.

## Project Data Link Files
Support for link-files within a Ghidra Project has been significantly expanded with this release and
with it a new file storage type has been introduced which can create some incompatibilities if
projects and repositories containing such files are used by older version of Ghidra or the Ghidra 
Server.

Previously, only external folder and file links were supported through the use of a Ghidra URL. With
12.0 the ability to establish internal folder and file links has been introduced.  A new storage 
format was adopted for link-files which avoids the use of a database and relies only on a 
light-weight property file only. Internal project links also allow for either absolute or relative 
links.  Due to Ghidra allowing a folder and file to have the same pathname, some ambiguities can 
result for Ghidra URL usage.  It is highly recommended that the use of conflicting folder and file 
pathnames be avoided.

The use of internally linked folders and files allows batch import processing to more accurately
reflect the native file-system and its use of symbolic links which allow for the same content to
be referenced by multiple paths.  Allowing this within a Ghidra project can avoid the potential for
importing content multiple times with the different paths and simply import once with additional 
link-files which reference it.  How best to leverage links very much depends on the end-user's 
needs and project file management preferences.  Special care must be taken when defining or 
traversing link-files to avoid external and circular references.

Additional Ghidra API methods have been provided or refined on the following classes to leverage 
link-files: `DomainFolder`, `DomainFile`, `LinkFile`, `LinkHandler`, `DomainFileFilter`, 
`DomainFileIterator`, etc.

## Importer Filesystem Mirroring
An option has been added to mirror the local filesystem when importing programs and their libraries.
Programs and libraries that exist on the local filesystem as symbolic links will have both their 
corresponding link file and resolved program file mirrored in the project. Filesystem mirroring
can also be used in headless mode with the new `-mirror` command line option.

## PyGhidra
PyGhidra 3.0.0 (compatible with Ghidra 12.0 and later) introduces many new Python-specific API 
methods with the goal of making the most common Ghidra tasks quick and easy, such as opening a 
project, getting a program, and running a GhidraScript. Legacy API functions such as 
`pyghidra.open_program()` and `pyghidra_run_script()` have been deprecated in favor of the new 
methods, which are outlined at https://pypi.org/project/pyghidra.

The default Python scripting engine has been changed in Ghidra 12.0 from Jython to PyGhidra.
Existing Jython scripts will need to include the `# @runtime Jython` script header in order to
continue running within the Jython environment.

## Z3 Concolic Emulation and Symbolic Summary
We've added an experimental Z3-based symbolic emulator, which runs as an "auxiliary" domain to the 
concrete emulator, effectively constructing what is commonly called a "concolic" emulator. The 
symbolic emulator creates Z3 expressions and branching constraints, but it only follows the path 
determined by concrete emulation. This is most easily accessed by installing the "SymbolicSummaryZ3"
extension (**File -> Install Extensions**) and then enabling the `Z3SummaryPlugin` in the 
Debugger or Emulator tool, which includes a GUI for viewing and sorting through the results. The Z3
emulator requires z3-4.13.0, available from https://github.com/Z3Prover/z3. Other versions may work,
but our current test configuration uses 4.13.0. Depending on the release and your platform, the
required libraries may be missing or incompatible. If this is the case, you will need to download
Z3, or build it from source with Java bindings, and install the libraries into 
`Ghidra/Extensions/SymbolicSummaryZ3/os/<platform>/`.

## Emulation API
The `PcodeEmulator` and related API has undergone substantial changes in preparation for integrating
our JIT-accelerated emulator into the GUI. Please see the **Notable API Changes** section of our 
[Change History](ChangeHistory.md). The goal is to facilitate integration by composition; whereas, 
it had previously required inheritance, which is now considered poor design. Essentially, we've 
introduced a set of callbacks that integrators can use to detect when certain things have happened
in emulation, as well as offer some control of machine-state behavior; e.g., to facilitate lazily 
loading from a snapshot.

Extensions that currently integrate via inheritance can continue to do so, but will still need to
apply some minimal changes to satisfy interface and constructor changes. The developers of such
extensions ought to consider porting their integrations to the compositional/callback-based
mechanism. A careful assessment may be required depending on the nature of the extension. Extensions
that merely integrate with emulation should consider the compositional/callback-based mechanism. 
Extensions that incorporate new domains (e.g. Z3) or novel behaviors (e.g. JIT) should continue 
using inheritance.

## Data Graph
Added a new data graph showing data relationships defined by references from one in memory defined data item
to another. The data graph can be displayed by clicking on a data item in the listing and
invoking the data graph action (**ctrl-g** or from the popup menu **data -> display data graph**). This action
will create a new data graph displaying the selected data item and its contents. From
that node, the graph can be expanded by following from or to references to that data item.

## Hide Function Variables
Added the ability to toggle the display of function variables (parameters and locals) within
the Code Browser Listing just below the function signature. The Variables display can be turned 
on/off globally via the popup menu toggle action (**Function -> Show/Hide All Variables**) or for
individual functions via an adjacent expand/collapse(+/-) icon.

## GhidraGo URL
Did you know Ghidra supports embedding URL links in web pages?  After setting up GhidraGo in
your preferred web browser and adding the GhidraGo plugin into Ghidra, clicking on a Ghidra URL link
will start Ghidra, open the program either locally or in a multi-user project, and then navigate
to the specified address in the specified program.  A Ghidra remote URL looks something like
(**ghidra://myrepo.org:13100/perf/9305e1d039/busybox_aarch64_fc0bdbc**).  You can provide
just the project path or include a path all the way to an address/symbol in a program within the
project.  See the Ghidra Help under GhidraGo for setup and more information.

## Processors
The NDS32, and RISCV variant AndeStar v5 processors have been added.  In addition the RISCV processor
has been re-factored to better handle RISCV custom extensions and the csreg register definitions have been
moved into a separate memory space.  The benefit of having an actual memory space for special function
registers is they can be seen, named, references created to them, data types applied at the location,
as well as default values supplied for a given binary sample.  We plan to do the same for other processors
such as the PowerPC.  There have also been numerous extensions and fixes added to the
AArch64, 8051, LoongArch, SuperH, Arm, Xtensa, x86, 68k, and many other processors.  Thanks for all
the community contributions!

## Additional Bug Fixes and Enhancements
Numerous other new features, improvements, and bug fixes are fully listed in the 
[Change History](ChangeHistory.md) file.
