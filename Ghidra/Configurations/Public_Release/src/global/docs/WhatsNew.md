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

# What's New in Ghidra 12.2
This release includes new features, enhancements, performance improvements, quite a few bug fixes,
and many pull-request contributions. Thanks to all those who have contributed their time, thoughts,
and code. The Ghidra user community thanks you too!

Major changes have been made to Ghidra Server and BSim PostgreSQL Server deployment and TLS/SSL
certificate requirements.  TLS/SSL server authentication is now enforced for all client/server
connections.  See __TLS/SSL Client/Server Changes__ below.

### The not-so-fine print: Please Read!
Ghidra 12.2 is fully backward compatible with project data from previous releases. However, programs
and data type archives which are created or modified in 12.2 may not be usable by an earlier Ghidra
version.

**IMPORTANT:** Jython support is not supported by default but is included with the release as an 
extension. An extra step is required to install it.  If you have Ghidra Jython scripts, you must 
either install the Jython Extension, convert your scripts to Python and run with PyGhidra, or 
convert your scripts to JAVA.

**IMPORTANT:** Ghidra 12.2 requires, at minimum, JDK 25 to run.

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

**NOTE:** Programs imported with a Ghidra Beta version or code built directly from source code
outside of a release tag may not be compatible, and may have flaws that won't be corrected by using
this new release.  Any programs analyzed from a beta or other local master source build should be
considered experimental and re-imported and analyzed with a release version.
	
Programs imported with previous release versions should upgrade correctly through various automatic
upgrade mechanisms.  However, there may be improvements or bug fixes in the import and analysis 
process that will provide better results than prior Ghidra versions.  You might consider comparing a
fresh import of any program you will continue to reverse engineer to see if the latest Ghidra 
provides better results.

**NOTE:** Ghidra Server: The Ghidra 12.2 server is compatible with older Ghidra 11.3.2 clients and 
later, although the presence of any newer link-files within a repository may not be handled properly
by client versions prior to 12.0, which lack support for the newer storage format.  Ghidra 12.1 
clients require Ghidra Server version 12.1/12.0.5 or newer compatible version. 

**NOTE:** Ghidra Server: Due to security fixes made to Ghidra and the Ghidra Server it is highly
recommended that older installation versions be updated to this latest release.  To ensure 
compatibility, older client version of Ghidra should also be upgraded.
	
## Security Related Fixes

### TLS/SSL Client/Server Changes
Ghidra Server and BSim PostgreSQL Server deployments now highly encourage the use of a CA-signed
server certificate.  In addition, Ghidra clients will now enforce server-authentication
for all SSL/TLS connections.  This was previously not the case with earlier versions of Ghidra.  
This server-authentication also applies to accessing servers accessed via the loopback/localhost 
interface, although the property `ghidra.disable.loopback.server.authentication` can be set `true` 
in `support/launch.properties` file to disable such local server authentication for testing.

A suitable keystore must be obtained from a CA signing-authority or a self-signed certificate file
may be generated but is not preferred.  If needed, the new `server/certTool` command provided with 
Ghidra may be used to assist with the keystore request and generation.  

Each client must ensure that trusted certificates are added to an appropriate trust store.
Ghidra clients now support the use of OS managed certificate trust stores as well as default trust
stores supplied with the Java installation.  For Windows and macOS, the system provided 
`User Certificate Manager` may be launched from the Ghidra projct window 
(Edit -> Manage Certificates...).  For Unix/Linux the property `ghidra.unix.default.cacerts` may be 
optionally specified in `support/launch.properties` to identify a directory path where unencrypted 
PEM or DER trusted certificate files may be added.  In the case of a server which uses a self-signed
certificate, that certificate would need to be added by each client as a trusted certificate. 
Otherwise, all the CA certificates in the server's CA-chain should be added if not already present.

#### Ghidra Server
If the `server/server.conf` file does not specify a `ghidra.keystore` the server will continue to 
auto-generate a temporary self-signed server certificate. However, when this occurs the server will 
now only listen for loopback connections on the localhost interface.  If remote connections are 
required, a proper keystore must be specified.  If local access only is acceptable, a Ghidra client
may set the `ghidra.disable.loopback.server.authentication=true` property in the 
`support/launch.properties` file with caution.  Otherwise, a keystore must be generated.

See `server/svrREADME.md` or `server/svrREADME.html` for more details.

#### BSim PostgreSQL Server
A BSim PostgreSQL data directory that was configured with a previous version of Ghidra will not have
any new constraints other than client connections now performing server authentication.  If using a 
self-signed certificate it will need to be added to client trust stores or a properly signed server 
certificate/keystore obtained.

New BSim PostgreSQL deployments should specify a server keystore when initialized.  If a keystore
is not specified, the server will use an auto-generated self-signed certificate which will need to 
be added to client trust stores.  When either a keystore is not specified, or the `trust` 
authentication mode is used (`--auth=trust`), the server will be configured to listen to loopback 
connections on the localhost interface only.

See Ghidra GUI Help Content related to BSim Database Configuration and `bsim_ctl` for more details.

### Ghidra Client - Server Allow List
Ghidra client-side applications will now impose the use of a __Server Allow List__ mechanism to 
help mitigate unintended server access.  This mechanism is currently used to restrict:

- Ghidra Server URL connections to unknown servers.  Explicit repository access via a shared project
  will cause that server to be implicitly added to the __Server Allow List__, and
- Clicking on URL links (e.g., http/https) within Ghidra listing comment annotations.

See `analyzeHeadlessREADME.md` for information related to use of __analyzeHeadless__ and the new
__support/updateServerAllowList__ command which can be used to manage the __Server Allow List__
entries.

## BSim PostgreSQL Deployment and Control (bsim_ctl)
Extensive changes have been made to the BSim PostgreSQL control script.  New `bsim_ctl` commands
have been added for initializing and reconfiguring a server deployment (`init`, `configure`).  Once
a deployment is configured, the following commands are used to manage its state: `start`, `stop`, 
and `restart`.  In addition, the ability to install as a Linux Service has been added using the 
commands `install-service` and `uninstall-service`. A new command `listusers` has also been added to
aid with user management.

When initializing or configuring a PostgreSQL server, `password` authentication mode is now the 
default if the `--auth` option is not specified.  This differs from previous releases which 
defaulted to `trust` authentication.  In general, use of `trust` authentication should be avoided.

## JDK 25
Ghidra now requires JDK 25 or later to run. Developing against JDK 25 has enabled the use of several
new language features. Some of the new features that Ghidra script and extension developers may now
use are outlined below:
- [Foreign Function & Memory API](https://openjdk.org/jeps/454)
- [Unnamed Variables & Patterns](https://openjdk.org/jeps/456)
- [Markdown Documentation Comments](https://openjdk.org/jeps/467)
- [Class-File API](https://openjdk.org/jeps/484)
- [Stream Gatherers](https://openjdk.org/jeps/485)
- [Scoped Values](https://openjdk.org/jeps/506)
- [Flexible Constructor Bodies](https://openjdk.org/jeps/513)

## Beta support for "Timeless Debugging"
We've completed several enhancements to the Debugger to better support "timeless" or "time-travel" 
debugging. This includes a native tool, based on Intel PIN, to capture execution traces in a format 
based on TENET. This format has a corresponding importer to load it into Ghidra's Debugger for 
further analysis. Three new UI components are included to aide in that analysis:

1. A breakpoint timeline, which displays hits for each breakpoint, color coded by kind (Execute, 
   Read, Write). Clicking a colored box navigates to the snapshot of the hit.
2. A dynamic call tree, which displays the execution history as a series of function calls, each 
   subroutine displayed as a child of its run-time parent. Call, Returns, and Tail Calls are 
   displayed, as observed. Clicking an item navigates to the snapshot of the observed call or 
   return.
3. A variable viewer, which tabulates all local variables known to the Listing and Decompiler along 
   with their storage, values, types, and typed-values.

These views can also be used with live Debugger targets, but with some caveats.
- To record a trace using PIN, see `Ghidra/Debug/Debugger-importers/data/TenetPlusPlus_PinTool`
- To enable the UI components, use **File &rarr; Configure** from the Debugger tool and open the 
  Experimental category.
- To import the Trace, use **File &rarr; Import** from the Debugger tool. You must first import the
  program image in the usual fashion, if you have not already. When importing the Trace, click
  Options and associate it with the image.

## Additional Bug Fixes and Enhancements
Numerous other new features, improvements, and bug fixes are fully listed in the 
[Change History](ChangeHistory.md) file.
