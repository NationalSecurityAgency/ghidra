# Debugger Developer's Guide

## Catalog of Dependencies

In addition to Ghidra's normal dependencies, you may want the following:

 * WinDbg for Windows x64
 * GDB 8.0 or later for Linux amd64/x86_64

The others (e.g., JNA) are handled by Gradle via Maven Central.

## Architecture Overview

There are several Eclipse projects each fitting into a larger architectural picture.
These all currently reside in the `Ghidra/Debug` directory, but will likely be re-factored into the `Framework` and `Feature` directories later.
Each project is listed "bottom up" with a brief description and status.

 * ProposedUtils - a collection of utilities proposed to be moved to other respective projects
 * AnnotationValidator - an experimental annotation processor for database access objects
 * Framework-TraceModeling - a database schema and set of interfaces for storing machine state over time
 * Framework-AsyncComm - a collection of utilities for asynchronous communication (packet formats and completable-future conveniences).
 * Framework-Debugging - specifies interfaces for debugger models and provides implementation conveniences.
 * Debugger - the collection of Ghidra plugins and services comprising the Debugger UI.
 * Debugger-agent-dbgeng - the connector for WinDbg (via dbgeng.dll) on Windows x64.
 * Debugger-agent-dbgmodel - an experimental connector for WinDbg Preview (with TTD, via dbgmodel.dll) on Windows x64.
 * Debugger-agent-dbgmodel-traceloader - an experimental "importer" for WinDbg trace files.
 * Debugger-agent-gdb - the connector for GDB (8.0 or later recommended) on UNIX.
 * Debugger-gadp - the connector for our custom wire protocol the Ghidra Asynchronous Debugging Protocol.
 * Debugger-jpda - an in-development connector for Java and Dalvik debugging via JDI (i.e., JDWP).
 * Debugger-sctl - a deprecated connector for the SCTL stub (cqctworld.org).

The Trace Modeling schema records machine state and markup over time.
It rests on the same database as Programs, allowing trace recordings to be stored in a Ghidra project and shared via a server, if desired.
Trace "recording" is a de facto requirement for displaying information in Ghidra's UI.
However, only the machine state actually observed by the user (or perhaps a script) is recorded.
For most use cases, the Trace is small and ephemeral, serving only to mediate between the UI components and the target's model.
It supports many of the same markup (e.g., disassembly, data types) as Programs, in addition to tracking active threads, loaded modules, breakpoints, etc.

Every model (or "adapter" or "connector" or "agent") implements the API specified in Framework-Debugging. As a general rule in Ghidra, no component is allowed to access a native API and reside in the same JVM as the Ghidra UI.
This allows us to contain crashes, preventing data loss.
To accommodate this requirement -- given that debugging native applications is almost certainly going to require access to native APIs -- we've developed the Ghidra Asynchronous Debugging Protocol.
This protocol is tightly coupled to Framework-Debugging, essentially exposing its methods via RMI.
The protocol is built using Google's Protobuf library, providing a potential path for agent implementations in alternative languages.
GADP provides both a server and a client implementation.
The server can accept any model which adheres to the specification and expose it via TCP; the client does the converse.
When a model is instantiated in this way, it is called an "agent," because it is executing in its own JVM.
The other connectors, which do not use native APIs, may reside in Ghidra's JVM and typically implement alternative wire protocols, e.g., JDWP and SCTL.
In both cases, the implementations inherit from the same interfaces.

The Debugger services maintain a collection of active connections and inspect each model for potential targets.
When a target is found, the service inspects the target environment and attempts to find a suitable opinion.
Such an opinion, if found, instructs Ghidra how to map the objects, addresses, registers, etc. from the target namespace into Ghidra's.
The target is then handed to a Trace Recorder which begins collecting information needed to populate the UI, e.g., the program counter, stack pointer, and the bytes of memory they refer to.

## Developing a new connector

So Ghidra does not yet support your favorite debugger?
It is tempting, exciting, but also daunting to develop your own connector.
Please finish reading this guide, and look carefully at the ones we have so far, and perhaps ask to see if we are already developing one.
Of course, in time you might also search the internet to see if others are developing one.
There are quite a few caveats and gotchas, the most notable being that this interface is still in quite a bit of flux.
When things go wrong, it could be because of, without limitation: 1) a bug on your part, 2) a bug on our part, 3) a design flaw in the interfaces, or 4) a bug in the debugger/API your adapting.
We are still in the process of writing up this documentation.
In the meantime, we recommend using the GDB and dbgeng.dll agents as examples.

You'll also need to provide launcher(s) so that Ghidra knows how to configure and start your connector.
Please provide launchers for your model in both configurations: as a connector in Ghidra's JVM, and as a GADP agent.
If your model requires native API access, you should only permit launching it as a GADP agent, unless you give ample warning in the launcher's description.
Look at the existing launchers for examples.
There are many model implementation requirements that cannot be expressed in Java interfaces.
Failing to adhere to those requirements may cause different behaviors with and without GADP.
Testing with GADP tends to reveal those implementation errors, but also obscures the source of client method calls behind network messages.

## Adding a new platform

If an existing connector exists for a suitable debugger on the desired platform, then adding it may be very simple.
For example, both the x86 and ARM platforms are supported by GDB, so even though we're currently focused on x86 support, we've provided the opinions needed for Ghidra to debug ARM platforms via GDB.
These opinions are kept in the "Debugger" project, not their respective "agent" projects.
We imagine there are a number of platforms that could be supported almost out of the box, except that we haven't written the necessary opinions, yet.
Take a look at the existing ones for examples.

In general, to write a new opinion, you need to know: 1) What the platform is called (including variant names) by the debugger, 2) What the processor language is called by Ghidra, 3) If applicable, the mapping of target address spaces into Ghidra's address spaces, 4) If applicable, the mapping of target register names to those in Ghidra's processor language.
In most cases (3) and (4) are already implemented by default mappers, so you can use those same mappers in your opinion.
Once you have the opinion written, you can try debugging and recording a target.
If Ghidra finds your opinion applicable to that target, it will attempt to record, and then you can work out the kinds from there.
Again, we have a bit of documentation to do regarding common pitfalls.

## Emulation

It may be tempting to write a "connector" for emulation, but we recommend against it.
We are exploring the inclusion of emulation as an integral feature of the UI.
Namely for interpolation between machines states recorded in a trace, and extrapolation into future machine states.
In other words, a connector for emulation is likely to be deprecated by our future work.

## Contributing

Whether submitting help tickets and pull requests, please tag those related to the debugger with "Debugger" so that we can triage them more quickly.

To set up your environment, in addition to the usual Gradle tasks, process the Protobuf specification for GADP:

```bash
gradle generateProto
```

If you already have an environment set up in Eclipse, please re-run `gradle prepDev eclipse` and import the new projects.
The Protobuf plugin for Gradle does not seem to export the generated source directory to the Eclipse project.
To remedy this, add `build/generated/source/proto/main/java` to the build path, and configure it to output to `bin/main`.