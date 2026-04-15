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

# What's New in Ghidra 12.1
This release includes new features, enhancements, performance improvements, quite a few bug fixes,
and many pull-request contributions. Thanks to all those who have contributed their time, thoughts,
and code. The Ghidra user community thanks you too!
	
### The not-so-fine print: Please Read!
Ghidra 12.1 is fully backward compatible with project data from previous releases. However, programs
and data type archives which are created or modified in 12.1 will not be usable by an earlier Ghidra
version.

**IMPORTANT:** Ghidra 12.1 requires, at minimum, JDK 21 to run.

**IMPORTANT:** To use the Debugger or do a full source distribution build, you will need Python3
(3.9 to 3.14 supported) installed on your system.

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

**NOTE:** Ghidra Server: The Ghidra 12.1 server is compatible with Ghidra 11.3.2 and later Ghidra
clients, although the presence of any newer link-files within a repository may not be handled properly
by client versions prior to 12.0 which lack support for the new storage format.  Ghidra 12.1 clients
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

## Bitfields
The Decompiler now recovers and displays the names of **bitfield** components in structured 
data-types, when analyzing code that manipulates them.

Low-level details of how code isolates an individual bitfield are simplified away in Decompiler 
output. Instead, the bitfield is displayed as a single logical value, by name, using standard field
access notation. Both expressions that *read from* or *write to* a bitfield can be recovered.

Many optimized expressions that read, write, or compare multiple bitfields at once can also be
broken out so that the individual bitfields are visible.

## Objective-C
The old Objective-C analyzers:
* Objective-C 2 Class
* Objective-C 2 Decompiler Message
* Objective-C Message (Prototype)

have been been reworked and replaced with versions that are more compatible with modern 
Objective-C binaries:
* Objective-C Type Metadata Analyzer
* Objective-C Message Analyzer

Where possible, calls to `_objc_msgSend()` and its variations (including `_objc_msgSend$` stubs) 
have been overridden to reference the actual target method (if discoverable), which results in a
much more user-friendly decompilation.

Additionally, a variety of AARCH64 call fixups have been implemented which further clean up 
decompilation, hiding much of the noise that things like Automatic Reference Counting (ARC) can 
generate.

## Debuginfod
We've added support for downloading DWARF debug files from HTTP[s] debuginfod servers, as well as 
searching the user's `$HOME/.cache/debuginfod_client` directory. You can configure these options in
the Code Browser tool's **Edit | DWARF External Debug Config** menu.

## Microsoft Demangler
We've added **Output Options** to the Microsoft Demangler to control the demangled output 
presentation, changing it from the standard form.

One option controls the inclusion of user-defined-type tags (e.g., "struct") when the type is used
as a function or template argument. When the tags are not applied, it can reduce the bifurcation
of symbols within namespaces where some namespaces have the tags and others do not.  This can happen
when non-mangled symbols do not include the tag and demangled symbols do.

Another option controls whether the standard **\`anonymous namespace'** is presented in a
**_anon_ABCD01234** form using its encoded anonymous namespace number.  When the new form is used,
it can reduce the commingling of symbols from two distinct anonymous namespaces into one generic
**\`anonymous namespace'**.  Note, however, that non-mangled symbols with the generic
**\`anonymous namespace'** (or one of its variants) can still be found in a program, coming from
other sources, such as PDB.  There is currently no simple way to try to match these with the new
encoded form; thus, using the encoded form can also create bifurcation in the namespace.

## Processors

## Additional Bug Fixes and Enhancements
Numerous other new features, improvements, and bug fixes are fully listed in the 
[Change History](ChangeHistory.md) file.
