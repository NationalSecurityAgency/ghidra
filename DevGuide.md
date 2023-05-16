# Developer's Guide

## Environment
* Primary Language: [Java][java]
* Secondary Languages: [C++][cpp], [Sleigh][sleigh], [Jython][jython]
* Integrated Development Environment: [Eclipse][eclipse]
* Build System: [Gradle][gradle]
* Source Control: [Git][git]

For specific information on required versions and download links please see the 
[README.md](README.md) file.

## Quickstart
Follow the [Advanced Development](README.md#advanced-development) instructions in the [
README.md](README.md) file to get your development environment setup quickly. 

## Licensing and Copyright
* Primary License: [Apache License 2.0][apache]
* Secondary Licenses: [See licenses directory](licenses)

If possible please try to stick to the [Apache License 2.0][apache]
license when developing for Ghidra.  At times it may be necessary to incorporate other compatible 
licenses into Ghidra.  Any GPL code must live in the top-level `GPL/` directory as a totally 
standalone, independently buildable Ghidra module.

If you are contributing code to the Ghidra project, the preferred way to receive credit/recognition 
is Git commit authorship.  Please ensure your Git credentials are properly linked to your GitHub 
account so you appear as a Ghidra contributor on GitHub.  We do not have a standard for putting 
authors' names directly in the source code, so it is discouraged.

## Common Gradle Tasks
Download non-Maven Central dependencies.  This creates a `dependencies` directory in the repository
root.
```
gradle -I gradle/support/fetchDependencies.gradle init
```

Download Maven Central dependencies and setup the repository for development.  By default, these 
will be stored at `$HOME/.gradle/`.
```
gradle prepdev
```

Generate nested Eclipse project files which can then be imported into Eclipse as "existing 
projects".
```
gradle cleanEclipse eclipse
```

Build native components for your current platform.  Requires native tool chains to be present.
```
gradle buildNatives
```

Manually compile sleigh files. Ghidra will also do this at runtime when necessary.
```
gradle sleighCompile
```

Build Javadoc:
```
gradle createJavadocs
```

Build Ghidra to `build/dist`.  This will be a distribution intended only to run on the platform on
which it was built.
```
gradle buildGhidra
```

**Tip:**  You may want to skip certain Gradle tasks to speed up your build, or to deal with
a problem later.  For example, perhaps you added some new source files and the build is failing 
because of unresolved IP header issues.  You can use the Gradle `-x <task>` command line argument to
prevent specific tasks from running:
```
gradle buildGhidra -x ip
```

## Known Issues
* There is a known issue in Gradle that can prevent it from discovering native toolchains on Linux 
  if a non-English system locale is being used. As a workaround, set the following environment 
  variable prior to running your Gradle task: `LC_MESSAGES=en_US.UTF-8`

## Offline Development Environment
Sometimes you may want to move the Ghidra repository to an offline network and do development there.
These are the recommended steps to ensure that you not only move the source repository, but all 
downloaded dependencies as well:

1. `gradle -I gradle/support/fetchDependencies.gradle init`
2. `gradle -g dependencies/gradle prepdev`
3. Move ghidra directory to different system
4. `gradle -g dependencies/gradle buildGhidra` (on offline system)

**NOTE**: The `-g` flag specifies the Gradle user home directory. The default is the `.gradle`
directory in the user’s home directory.  Overriding it to be inside the Ghidra repository will
ensure that all maven central dependencies that were fetched during the `prepdev` task will be moved
along with the rest of the repo.

## Developing GhidraDev Eclipse Plugin
Developing the GhidraDev Eclipse plugin requires the 
_Eclipse PDE (Plug-in Development Environment)_, which can be installed via the Eclipse marketplace.
It is also included in the _Eclipse IDE for RCP and RAP Developers_. To generate the GhidraDev 
Eclipse projects, execute:

```
gradle eclipse -PeclipsePDE
```

Import the newly generated GhidraDev projects into an Eclipse that supports this type of project. 

__Note:__ If you are getting compilation errors related to PyDev and CDT, go into Eclipse's 
preferences, and under _Target Platform_, activate _/Eclipse GhidraDevPlugin/GhidraDev.target_.

See [GhidraDevPlugin/build_README.txt](GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build_README.txt)
for instructions on how to build the GhidraDev plugin.

## Running tests
To run unit tests, do:
```
gradle unitTestReport
```

For more complex integration tests, do:
```
gradle integrationTest
```

For running both unit and integration tests and to generate a report do:
```
gradle combinedTestReport
```

## Setup build in CI

For running tests in headless mode on Linux, in a CI environment, or in Docker, first do:
```
Xvfb :99 -nolisten tcp &
export DISPLAY=:99
```
This is required to make AWT happy.

## Building Supporting Data

Some features of Ghidra require the curation of rather extensive databases. These include the Data 
Type Archives and Function ID Databases, both of which require collecting header files and libraries
for the relevant SDKs and platforms. Much of this work is done by hand. The archives included in our
official builds can be found in the [ghidra-data] repository.

### Building Data Type Archives

This task is often done manually from the Ghidra GUI, and the archives included in our official 
build require a fair bit of fine tuning.
1. From the CodeBrowser, select __File -> Parse C Source__
2. From here you can create and configure
parsing profiles, which lists headers and pre-processor options.
3. Click _Parse to File_ to create the Data Type Archive.
4. The result can be added to an installation or source tree by copying it to 
`Ghidra/Features/Base/data/typeinfo`.

### Building FID Databases

This task is often done manually from the Ghidra GUI, and the archives included in our official 
build require a fair bit of fine tuning. You will first need to import the relevant libraries from 
which you'd like to produce a FID database. This is often a set of libraries from an SDK. We include
a variety of Visual Studio platforms in the official build. The official .fidb files can be found in
the [ghidra-data][ghidra-data] repository.

1. From the CodeBrowser, select __File -> Configure__
2. Enable the "Function ID" plugins, and close the dialog.
3. From the CodeBrowser, select __Tools -> Function ID -> Create new empty FidDb__.
4. Choose a destination file.
5. Select __Tools -> Function ID -> Populate FidDb__ from programs.
6. Fill out the options appropriately and click OK.

If you'd like some details of our fine tuning, take a look at [building_fid.txt](Ghidra/Features/FunctionID/data/building_fid.txt).

## Debugger Development

### Additional Dependencies

In addition to Ghidra's normal dependencies, you may want the following:

 * WinDbg for Windows x64
 * GDB 8.0 or later for Linux amd64/x86_64
 * LLDB 13.0 for macOS

The others (e.g., JNA) are handled by Gradle via Maven Central.

### Architecture Overview

There are several Eclipse projects each fitting into a larger architectural picture.
These all currently reside in the `Ghidra/Debug` directory, but will likely be re-factored into the
`Framework` and `Feature` directories later. Each project is listed "bottom up" with a brief 
description and status.

 * ProposedUtils - a collection of utilities proposed to be moved to other respective projects
 * AnnotationValidator - an experimental annotation processor for database access objects
 * Framework-TraceModeling - a database schema and set of interfaces for storing machine state over
 time
 * Framework-AsyncComm - a collection of utilities for asynchronous communication (packet formats
 and completable-future conveniences).
 * Framework-Debugging - specifies interfaces for debugger models and provides implementation
 conveniences.
 * Debugger - the collection of Ghidra plugins and services comprising the Debugger UI.
 * Debugger-agent-dbgeng - the connector for WinDbg (via dbgeng.dll) on Windows x64.
 * Debugger-agent-dbgmodel - an experimental connector for WinDbg Preview (with TTD, via 
 dbgmodel.dll) on Windows x64.
 * Debugger-agent-dbgmodel-traceloader - an experimental "importer" for WinDbg trace files.
 * Debugger-agent-gdb - the connector for GDB (8.0 or later recommended) on UNIX.
 * Debugger-swig-lldb - the Java language bindings for LLDB's SBDebugger, also proposed upstream.
 * Debugger-agent-lldb - the connector for LLDB (13.0 required) on macOS, UNIX, and Windows.
 * Debugger-gadp - the connector for our custom wire protocol the Ghidra Asynchronous Debugging 
 Protocol.
 * Debugger-jpda - an in-development connector for Java and Dalvik debugging via JDI (i.e., JDWP).

The Trace Modeling schema records machine state and markup over time.
It rests on the same database framework as Programs, allowing trace recordings to be stored in a
Ghidra project and shared via a server, if desired. Trace "recording" is a de facto requirement for
displaying information in Ghidra's UI. However, only the machine state actually observed by the user
(or perhaps a script) is recorded. For most use cases, the Trace is small and ephemeral, serving
only to mediate between the UI components and the target's model. It supports many of the same 
markup (e.g., disassembly, data types) as Programs, in addition to tracking active threads, loaded
modues, breakpoints, etc.

Every model (or "adapter" or "connector" or "agent") implements the API specified in 
Framework-Debugging. As a general rule in Ghidra, no component is allowed to access a native API and
reside in the same JVM as the Ghidra UI. This allows us to contain crashes, preventing data loss. To
accommodate this requirement -- given that debugging native applications is almost certainly going 
to require access to native APIs -- we've developed the Ghidra Asynchronous Debugging Protocol. This
protocol is tightly coupled to Framework-Debugging, essentially exposing its methods via RMI. The 
protocol is built using Google's Protobuf library, providing a potential path for agent 
implementations in alternative languages. GADP provides both a server and a client implementation. 
The server can accept any model which adheres to the specification and expose it via TCP; the client
does the converse. When a model is instantiated in this way, it is called an "agent," because it is
executing in its own JVM. The other connectors, which do not use native APIs, may reside in Ghidra's
JVM and typically implement alternative wire protocols, e.g., JDWP. In both cases, the 
implementations inherit from the same interfaces.

The Debugger services maintain a collection of active connections and inspect each model for 
potential targets. When a target is found, the service inspects the target environment and attempts
to find a suitable opinion. Such an opinion, if found, instructs Ghidra how to map the objects, 
addresses, registers, etc. from the target namespace into Ghidra's. The target is then handed to a 
Trace Recorder which begins collecting information needed to populate the UI, e.g., the program 
counter, stack pointer, and the bytes of memory they refer to.

### Developing a new connector

So Ghidra does not yet support your favorite debugger?
It is tempting, exciting, but also daunting to develop your own connector.
Please finish reading this guide, and look carefully at the ones we have so far, and perhaps ask to
see if we are already developing one. Of course, in time you might also search the internet to see 
if others are developing one. There are quite a few caveats and gotchas, the most notable being that
this interface is still in quite a bit of flux. When things go wrong, it could be because of, 
without limitation: 1) a bug on your part, 2) a bug on our part, 3) a design flaw in the interfaces,
or 4) a bug in the debugger/API you're adapting. We are still in the process of writing up this
documentation. In the meantime, we recommend using the GDB and dbgeng.dll agents as examples.

You'll also need to provide launcher(s) so that Ghidra knows how to configure and start your 
connector. Please provide launchers for your model in both configurations: as a connector in 
Ghidra's JVM, and as a GADP agent. If your model requires native API access, you should only permit
launching it as a GADP agent, unless you give ample warning in the launcher's description. Look at 
the existing launchers for examples. There are many model implementation requirements that cannot be
expressed in Java interfaces. Failing to adhere to those requirements may cause different behaviors 
with and without GADP. Testing with GADP tends to reveal those implementation errors, but also 
obscures the source of client method calls behind network messages. We've also codified (or 
attempted to codify) these requirements in a suite of abstract test cases. See the `ghidra.dbg.test`
package of Framework-Debugging, and again, look at existing implementations.

### Adding a new platform

If an existing connector exists for a suitable debugger on the desired platform, then adding it may
be very simple. For example, both the x86 and ARM platforms are supported by GDB, so even though 
we're currently focused on x86 support, we've provided the opinions needed for Ghidra to debug ARM
platforms (and several others) via GDB. These opinions are kept in the "Debugger" project, not their
respective "agent" projects. We imagine there are a number of platforms that could be supported 
almost out of the box, except that we haven't written the necessary opinions, yet. Take a look at 
the existing ones for examples.

In general, to write a new opinion, you need to know: 1) What the platform is called (including 
variant names) by the debugger, 2) What the processor language is called by Ghidra, 3) If 
applicable, the mapping of target address spaces into Ghidra's address spaces, 4) If applicable, the
mapping of target register names to those in Ghidra's processor language. In most cases (3) and (4) 
are already implemented by default mappers, so you can use those same mappers in your opinion. Once 
you have the opinion written, you can try debugging and recording a target. If Ghidra finds your 
opinion applicable to that target, it will attempt to record, and then you can work out the kinds 
from there. Again, we have a bit of documentation to do regarding common pitfalls.

### Emulation

The most obvious integration path for 3rd-party emulators is to write a "connector." However, p-code
emulation is now an integral feature of the Ghidra UI, and it has a fairly accessible API. Namely, 
for interpolation between machines states recorded in a trace, and extrapolation into future machine
states. Integration of such emulators may still be useful to you, but we recommend trying the p-code
emulator to see if it suits your needs for emulation in Ghidra before pursuing integration of 
another emulator.

### Contributing

Whether submitting help tickets and pull requests, please tag those related to the debugger with 
"Debugger" so that we can triage them more quickly.

To set up your environment, in addition to the usual Gradle tasks, process the Protobuf 
specification for GADP:

```bash
gradle generateProto
```

If you already have an environment set up in Eclipse, please re-run `gradle prepDev eclipse` and 
import the new projects.


[java]: https://dev.java
[cpp]: https://isocpp.org
[sleigh]: https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/languages/index.html
[jython]: https://www.jython.org
[eclipse]: https://www.eclipse.org/downloads/
[gradle]: https://gradle.org
[git]: https://git-scm.com
[apache]: https://www.apache.org/licenses/LICENSE-2.0
[fork]: https://docs.github.com/en/get-started/quickstart/fork-a-repo
[ghidra-data]: https://github.com/NationalSecurityAgency/ghidra-data
[DbgGuide]: DebuggerDevGuide.md
