
# Adding a debugger

This module walks you through an example of how to add a debugger agent to Ghidra.
It has no exercises and is certainly not the only way to implement an agent, but hopefully contains some useful pointers and highlights some pit-falls that you might encounter.
The example traces the implementation of an actual agent &mdash; the agent for *Meta*'s **drgn** debugger, which provides a scriptable, albeit read-only, interface to the running Linux kernel, as well as user-mode and core-dump targets.

## Debugger documentation

- Recommended reading: **drgn** (<https://github.com/osandov/drgn>)
- Also: **drgn (docs)** (<https://drgn.readthedocs.io/en/latest>)

## Anatomy of a Ghidra debugger agent

To support debugging on various platforms, the Ghidra debugger has *agents*, i.e. clients capable of receiving information from a native debugger and passing it to the Ghidra GUI.
They include the **dbgeng** agent that supports Windows debuggers, the **gdb** agent for gdb on a variery of platforms, the **lldb** agent for macOS and Linux, and the **jpda** agent for Java.
All but the last are written in Python 3, and all communicate with the GUI via a protobuf-based protocol described in [Debugger-rmi-trace](../../../Ghidra/Debug/Debugger-rmi-trace/src/main/proto/trace-rmi.proto).

At the highest level, each agent has four elements (ok, a somewhat arbitrary division, but...):

* [`debugger-launchers`](../../../Ghidra/Debug/Debugger-agent-drgn/data/debugger-launchers) &ndash; A set of launchers, often a mixture of `.bat`,`.sh`, and sometime `.py` scripts
* [`schema.xml`](../../../Ghidra/Debug/Debugger-agent-drgn/src/main/py/src/ghidradrgn/schema.xml) &ndash; An object-model schema. (While expressed in XML, this is not an "XML schema".)
* [`src/ghidradrgn`](../../../Ghidra/Debug/Debugger-agent-drgn/src/main/py/src/ghidradrgn) &ndash; Python files for architecture, commands, hooks, methods, and common utility functions
* [`build.gradle`](../../../Ghidra/Debug/Debugger-agent-drgn/build.gradle) &ndash; Build logic

Large portions of each are identical or similar across agents, so, as a general strategy, copying an existing agent and renaming all agent-specific variables, methods, etc. is not the worst plan of action. Typically, this leads to large chunks of detritus that need to be edited out late in the development process.

## drgn as an Example

### The first launcher &mdash; `local-drgn.sh`

The initial objective is to create a shell that sets up the environment variables for parameters we'll need and invokes the target. 
For this project, I originally started duplicating the **lldb** agent and then switched to the **dbgeng** agent. 
Why? The hardest part of writing an agent is getting the initial launch pattern correct.
**drgn** is itself written in Python.
While gdb and lldb support Python as scripting languages, their cores are not Python-based.
For these debuggers, the launcher runs the native debugger and instructs it to load our plugin, which is the agent. 
The dbgeng agent inverts this pattern, i.e. the agent is a Python application that uses the **Pybag** package to access the native *kd* interface over COM.
**drgn** follows this pattern.

That said, a quick look at the launchers in the **dbgeng** project (under [`debugger-launchers`](../../../Ghidra/Debug/Debugger-agent-dbgeng/data/debugger-launchers)) shows `.bat` files, each of which calls a `.py` file in [`data/support`](../../../Ghidra/Debug/Debugger-agent-dbgeng/data/support). 
As **drgn** is a Linux-only debugger, we need to convert the `.bat` examples to `.sh`. 
Luckily, the conversion is pretty simple: most line annotations use `#` in place of `::` and environment variables are referenced using `$VAR` in place of `%VAR%`.

The syntax of the `.sh` is typical of any *\*nix* shell. 
In addition to the shell script, a launcher include a metadata header to populate its menu and options dialog.
Annotations include:

* A `#!` line for the shell invocation
* The Ghidra license
* A `#@title` line for the launcher name
* A `#@desc`-annotated HTML description, as displayed in the launch dialog
* `#@menu-group` for organizing launchers 
* `#@icon` for an icon
* `#@help` the help file and anchor
* Some number of `#@arg` variables, usually only one to name the executable image
* `#@args` specifies the remainder of the arguments, passed to a user-mode target if applicable
* Some number of `#@env` variables referenced by the Python code
 
While the **drgn** launcher does not use `@arg` or `@args`, there are plentiful examples
in the [**gdb** project](../../../Ghidra/Debug/Debugger-agent-gdb/data/debugger-launchers).
The `#@env` lines are composed of the variable name (usually in caps), its type, default value, a label for the dialog if the user need to be queried, and a description.
The syntax looks like:

* `#@env` *Name* `:` *Type* [ `!` ] `=` *DefaultValue* *Label* *Description*

where `!`, if present, indicates the option is required.

For **drgn**, invoking the `drgn` command directly saves us a lot of the work involved in getting the environment correct.
We pass it our Python launcher `local-drgn.py` instead of allowing it to call `run_interactive`, which does not return.
Instead, we created an instance of `prog` based on the parameters, complete the Ghidra-specific initialization, and call `run_interactive(prog)` ourselves.

The Python script needs to do the setup work for Ghidra and for **drgn**.
A good start is to try to implement a script that calls the methods for `connect`, `create`, and `start`, with `create` doing as little as possible initially.
This should allow you to work the kinks out of `arch.py` and `util.py`.

For this particular target, there are some interesting wrinkles surrounding the use of `sudo` (required for most targets) which complicate where wheels are installed (i.e. it is pretty easy to accidentally mix user-local and system `site-packages`).
Additionally, the `-E` parameter is required to ensure that the environment variable we defined get passed to the root environment. 
In the cases where we use `sudo`, the first message printed in the interactive shell will be the request for the user's password.

### The schema

The schema, specified in `schema.xml`, provides a basic structure for Ghidra's **Model** View and allows Ghidra to identify and locate various interfaces that are used to populate the GUI.
For example, the *Memory* interface identifies the container for items with the interface *MemoryRegion*, which provide information used to fill the **Memory** View.
Among the important interfaces are *Process*, *Thread*, *Frame*, *Register*, *MemoryRegion*, *Module*, and *Section*.
These interfaces are "built into" Ghidra so that it can identify which objects provide specific information and commands.

For the purposes of getting started, it's easiest to clone the **dbgeng** schema and modify it as needed.
Again, this will require substantial cleanup later on, but, as schema errors are frequently subtle and hard to identify, revisiting is probably the better approach.
`MANIFEST.in` should be modfied to reflect the schema's path.

### The build logic

Similarly, `build.gradle` can essentially be cloned from **dbgeng**, with the appropriate change to `eclipse.project.name`.
For the most part, you need only apply the `distributableGhidraModule.gradle` and `hasPythonPackage.gradle` scripts.
If further customization is needed, consult other examples in the Ghidra project and Gradle's documentation.

Not perhaps directly a build logic item, but `pyproject.toml` should be modified to reflect the agent's version number (by convention, Ghidra's version number).

### The Python files

At this point, we can start actually implementing the **drgn** agent. 
`arch.py` is usually a good starting point, as much of the initial logic depends on it. 
For `arch.py`, the hard bit is knowing what maps to what.
The `language_map` converts the debugger's self-reported architecture to Ghidra's language set.
Ghidra's languages are mapped to a set of language-to-compiler maps, which are then used to map the debugger's self-reported language to Ghidra's compiler. 
Certain combinations are not allowed because Ghidra has no concept of that language-compiler combination.
For example, x86 languages never map to `default`.
Hence, the need for a `x86_compiler_map`, which defaults to something else (in this case, `gcc`).

After `arch.py`, a first pass at `util.py` is probably warranted. 
In particular, the version info is used early in the startup process.
A lot of this code is not relevant to our current project, but at a minimum we want to implement (or fake out) methods such as `selected_process`, `selected_thread`, and `selected_frame`. 
In this example, there probably won't be more than one session or one process. 
Ultimately, we'll have to decide whether we even want *Session* in the schema. 
For now, we're defaulting session and process to 0, and thread to 1, as 0 is invalid for debugging the kernel. 
(Later, it becomes obvious that the attached pid and `prog.main_thread().tid` make sense for user-mode debugging, and `prog.crashed_thread().tid` makes sense for crash dump debugging.)

With `arch.py` and `util.py` good to a first approximation, we would normally start implementing `put` methods in `commands.py` for various objects in the **Model** View, starting at the root of the tree and descending through the children. 
Again, *Session* and *Process* are rather poorly-defined, so we skip them (leaving one each) and tackle *Threads*. 
Typically, for each iterator in the debugger API, two commands get implemented &mdash; one internal method that does the actual work, e.g. `put_threads()` and one invokable method that wraps this method in a (potentialy batched) transaction, e.g. `ghidra_trace_put_threads()`.
The internal methods are meant to be called by other Python code, with the caller assumed to be responsible for setting up the transaction.
The `ghidra_trace`-prefixed methods are meant to be part of the custom CLI command set which the user can invoke and therefore should set up the transaction.
The internal method typically creates the path to the container using patterns for the container, individual keys, and the combination, e.g. `THREADS_PATTERN`, `THREAD_KEY_PATTERN`, and `THREAD_PATTERN`.
Patterns are built up from other patterns, going back to the root.
A trace object corresponding to the debugger object is created from the path and inserted into the trace database.

Once this code has been tested, attributes of the object can be added to the base object using `set_value`. 
Attributes that are not primitives can be added using the pattern create-populate-insert, i.e. we call `create_object` with extensions to the path, populate the object's children, and call `insert` with the created object.
In many cases (particularly when populating an object's children is expensive), you may want to defer the populate step, effectively creating a placeholder that can be populated on-demand.
The downside of this approach, of course, is that *refresh* methods must be added to populate those nodes.

As an aside, it's probably worth noting the function of `create_object` and `insert`.
Objects in the trace are maintained in a directory tree, with links (and backlinks) allowed, whose visible manifestation is the **Model** View.
As such, operations on the tree follow the normal procedure for operations on a graph.
`create_object` creates a node but not any edges, not even the implied ("canonical") edge from parent to child.
`insert` creates the canonical edge.
Until that edge exists, the object is not considered to be "alive", so the lifespan of the edge effectively encodes the object's life.
Following the create-populate-insert pattern, minimizes the number of events that need to be processed.

Having completed a single command, we can proceed in one of two directions &mdash; we can continue implementing commands for other objects in the tree, or we can implement matching *refresh* methods in `methods.py` for the completed object. 
`methods.py` also requires patterns which are used to match a path to a trace object, usually via `find_x_by_pattern` methods. 
The `refresh` methods may or may not rely on the `find_by` methods depending on whether the matching command needs parameters.
For example, we may want to assume the `selected_thread` matches the current object in the view, in which case it can be used to locate that node, or we may want to force the method to match on the node if the trace object can be easily matched to the debugger object, or we may want to use the node to set `selected_thread`.

The concept of focus in the debugger is fairly complicated and a frequent source of confusion.
In general, we use *selected* to represent the GUI's current focus, typically the node in the **Model** or associated views which the user has selected.
In some sense, it represents the process, thread, or frame the user is interested in. 
It also may differ from the *highlighted* node, chosen by a single-click (versus a double-click which sets the *selection*).
By contrast, the native debugger has its own idea of focus, which we usually describe as *current*.
(This concept is itself complicated by distinctions between the *event* object, e.g. which thread the debugger broke on, and the *current* object, e.g. which thread is being inspected.)
*Current* values are pushed "up" to Ghidra's GUI from the native debugger; *selected* values are pushed "down" to the native debugger from Ghidra.
To the extent possible, it makes sense to synchronize these values.
In other words, in most cases, a new *selection* should force a change in the set of *current* objects, and an event signaling a change in the *current* object should alter the GUI's set of *selected* objects.
(Of course, care needs to be taken not to make this a round-trip cycle.)

`refresh` methods (and others) are often annotated in several ways.
The `@REGISTRY.method` annotation makes the method available to the GUI.
It specifies the `action` to be taken and the `display` that appears in the GUI pop-up menu. 
*Actions* may be purely descriptive or may correspond to built-in actions taken by the GUI, e.g. `refresh` and many of the control methods, such as `step_into`. 
Parameters for the methods may be annotated with `sch.Schema` (conventionally on the first parameter) to indicate the nodes to which the method applies, and with `ParamDesc` to describe the parameter's type and label for pop-up dialogs. 
After retrieving necessary parameters, `refresh` methods invoke methods from `commands.py` wrapped in a transaction.

For **drgn**, we implemented `put`/`refresh` methods for threads, frames, registers (`putreg`), and local variables, then modules and sections, memory and regions, the environment, and finally processes.
We also implemented `putmem` using the **drgn**'s `read` API.
*Symbols* was another possibility, but, for the moment, populating symbols seemed to expensive.
Instead, `retrieve_symbols` was added to allow per-pattern symbols to be added.
Unfortunately, the **drgn** API doesn't support wildcards, so eventually some other strategy will be necessary.

The remaining set of Python functions, `hooks.py`, comprises callbacks for various events sent by the native debugger. 
The current **drgn** code has no event system.
A set of skeletal methods has been left in place as (a) we can use the single-step button as a stand-in for "update state", and (b) some discussion exists in the **drgn** user forums regarding eventually implementing more control functionality.
For anyone implementing `hooks.py`, the challenging logic resides in the event loop, particularly if there is a need to move back-and-forth between the debugger and a *repl*. 
Also, distinctions need to be made between control commands, which wait for events, and commands which rely on a callback but complete immediately. 
As a rule-of-thumb, we *push* to Ghidra, i.e. Ghidra issue requests asynchronously and the agent must update the trace database.

### Revisiting the schema

At this point, revisiting and editing the schema may be called for.
For example, for **drgn**, it's not obvious that there can ever be more than one session, so it may be cleaner to embed *Processes* at the root. 
This, in turn, requires editing the `commands.py` and `methods.py` patterns. 
Similarly, as breakpoints are not supported, the breakpoint-related entries may safely be deleted.

In general, the schema can be structured however you like, but there are several details worth mentioning. 
Interfaces generally need to be respected for various functions in the GUI to work. 
Process, thread, frame, module, section, and memory elements can be named arbitrarily, but their interfaces must be named correctly.
Additionally, the logic for finding objects in the tree is quite complicated. 
If elements need be traversed as part of the default search process, their containers must be tagged `canonical`.
If attributes need to be traversed, their parents should have the interface `Aggregate`. 

Each entry may have `elements` of the same type ordered by keys, and `attributes` of arbitrary type. 
The `element` entry describes the schema for all elements; the schema for attributes may be given explicitly using named `attribute` entries or defaulted using the unnamed `attribute` entry, typically `<attribute schema="VOID">` or `<attribute schema="ANY">`. 
The schema for any element in the **Model** View is visible using the hover, which helps substantially when trying to identify schema traversal errors.

Schema entries may be marked `hidden=yes` with the obvious result. 
Additionally, certain attribute names and schema have special properties.
For example, `_display` defines the visible ID for an entry in the **Model** tree, and `ADDRESS` and `RANGE` mark attributes which are navigable.


### Unit tests 

The hardest part of writing unit tests is almost always getting the first test to run, and the easiest unit tests, as with the Python files, are those for `commands.py`.
For **drgn**, as before, we're using **dbgeng** as the pattern, but several elements had to be changed.
Because the launchers execute a script, we need to amend the `runThrowError` logic (and, more specifically, the `execInPython` logic) in [`AbstractDrgnTraceRmiTest`](../../../Ghidra/Test/DebuggerIntegrationTest/src/test.slow/java/agent/drgn/rmi/AbstractDrgnTraceRmiTest.java) with a `ProcessBuilder` call that takes a script, rather than writing the script to stdin. 
While there, we can also trim out the unnecessary helper logic around items like breakpoints, watchpoints, etc. from all of the test classes.

JUnits for `methods.py` follow a similar pattern, but, again, getting the first one to run is often the most difficult. 
For **drgn**, we've had to override the timeouts in `waitForPass` and `waitForCondition`.
After starting with hardcoded paths for the test target, we also had to add logic to re-write the `PREAMBLE` on-the-fly in `execInDrgn`. 
Obviously, with no real `hooks.py` logic, there's no need for `DrgnHooksTest`.

Of note, we've used the gdb `gcore` command to create a core dump for the tests.
Both user- and kernel-mode require privileges to run the debugger, and, for testing, that's not ideal.
[`build.gradle`](../../../Ghidra/Test/DebuggerIntegrationTest/build.gradle) for IntegrationTest projext will also need to be modified to include the new debugger package.

### Documentation

The principal piece of documentation for all new debuggers is a description of the launchers.
Right now, the [`TraceRmiLauncherServicePlugin.html`](../../../Ghidra/Debug/Debugger-rmi-trace/src/main/help/help/topics/TraceRmiConnectionManagerPlugin/TraceRmiLauncherServicePlugin.html) file in `Debug/Debugger-rmi-trace` contains all of this information.
Detail to note: the `#@help` locations in the launchers themselves ought to match the HTML tags in the file, as should the launcher names.

### Extended features

Once everything else is done, it may be worth considering additional functionality specific to the debugger. This can be made available in either `commands.py` or `methods.py`.
For **drgn**, we've added `attach` methods that allow the user to attach to additional programs.