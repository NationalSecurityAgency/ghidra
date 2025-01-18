
# A Tour of the Debugger

This module assumes you have completed the [Getting Started](A1-GettingStarted.md) module.
If not, please go back.

This module will briefly introduce each window in the Ghidra Debugger.
We assume some familiarity with trap-and-trace debugging.
If you have not used GDB or a similar debugger before, you may find the Ghidra Debugger difficult to grasp.

If you would like your tool to look more or less like the one presented in the screenshot here,
launch `termmines` from the Debugger using GDB.

## The Debugger Tool

Like the CodeBrowser tool, the Debugger tool is a preconfigured collection of plugins and panels that present Ghidra's dynamic analysis features.
You may re-configure, save, export, import, etc. the tool to fit your preferences.
For reference, here is a screenshot of the default configuration after launching `termmines`:

![Debugger tool after launching termmines](images/GettingStarted_DisassemblyAfterLaunch.png)

### Toolbar

Many of the buttons in the global toolbar are the same as in the CodeBrowser.
Coincidentally, in the screenshot, the debugger-specific buttons start just above the Dynamic Listing in the global toolbar.
They are:

* ![launch button](images/debugger.png) **Launch**:
  This launches the current program (from the Static Listing) using a suitable back-end debugger.
  The drop-down menu provides a selection of previously-used launchers and a sub-menu of all available launchers.
  Clicking the button will use the most recent configuration, whether or not it succeeded.
* ![emulate button](images/process.png) **Emulate**:
  To be covered in a later module.
  This will load the current program (from the Static Listing) into the emulator.
* ![mode button](images/record.png) **Control Mode**:
  This drop-down menu sets the mode of the controls and machine state edits.
  By default, all actions are directed to the back-end debugger.
* ![resume button](images/resume.png) **Resume**:
  Resume execution.
  This is equivalent to `continue` in GDB.
* ![interrupt button](images/interrupt.png) **Interrupt**:
  Interrupt, suspend, pause, break, etc.
  This is equivalent to **`CTRL`-`C`** or `interrupt` in GDB.
* ![kill button](images/kill.png) **Kill**:
  Kill, terminate, etc.
  This is equivalent to `kill` in GDB.
* ![disconnect button](images/disconnect.png) **Disconnect**:
  Disconnect from the back-end debugger.
  Typically, this will also end the session.
  It is equivalent to `quit` in GDB.
* ![step into button](images/stepinto.png) **Step Into**, ![step over button](images/stepover.png) **Step Over**, ![step out button](images/stepout.png) **Step Out**, ![step last button](images/steplast.png) **Step [Extended]**:
  These buttons step in various ways.
  In order, the equivalent commands in GDB are `stepi`, `nexti`, and `finish`.
  Step [Extended] represents additional step commands supported by the back end. GDB provides **Advance** and **Return**.

### Windows

Starting at the top left and working clockwise, the windows are:

* The **Debug Console** window:
  (Not to be confused with the CodeBrowser's Console window.)
  This lists problems, diagnostics, progress, and recommendations throughout the tool.
  Some problems are presented with remedial actions, which may expedite your workflow or aid in troubleshooting.
* The **Connections** window:
  This is stacked below the Debug Console.
  This lists active sessions or connections.
  From here, you can establish new sessions or terminate existing sessions.
* The **Dynamic Listing** window:
  This is the primary means of examining the instructions being executed.
  By default, it follows the program counter and disassembles from there until the next control transfer instruction.
  It supports many of the same operations as the Static Listing, including patching.
  The nearest equivalent in GDB is something like `x/10i $pc`.
  The tabs at the top list the active traces.
  Traces with a ![record](images/record.png) icon represent live targets.
  The nearest equivalent to the tabs in GDB is `info inferiors`.
* The **Breakpoints** window:
  This is on the right.
  It lists and manages the breakpoints among all open program databases and running targets.
  The nearest equivalent in GDB is `info break`.
* The **Registers** window:
  This is stacked below the Breakpoints window.
  It displays and edits the register values for the current thread.
  The nearest equivalent in GDB is `info registers`.
* The **Memory** window:
  This is stacked below the Breakpoints window.
  It displays the raw bytes of memory from the current trace or target.
  It supports many of the same operations as the CodeBrowser's Bytes window, including patching.
* The **Decompiler** window:
  While not a dynamic analysis window, it bears mentioning how this operates with the Debugger.
  It is stacked below the Breakpoints window, more or less in the same place as in the CodeBrowser.
  The Dynamic listing strives to synchronize Ghidra's static analysis windows with the dynamic target.
  So long as the correct program database is imported and mapped at the program counter, this window should display decompilation of the function containing it.
* The **Modules** window:
  This is stacked below the Registers window.
  It displays the images (and sections, if applicable) loaded by the target.
  The equivalent in GDB is `maintenance info sections`.
  Note that this differs from the Regions window.
* The **Terminal** window:
  This is on the bottom right.
  This is a terminal emulator providing a command-line interface to the back-end debugger and/or target I/O.
  It is useful for diagnostics or for issuing commands that do not have a button in the GUI.
  Some may also prefer to command the debugger from here rather than the GUI.
  In some configurations, the target may have its own Terminal, separate from the back-end debugger's.
* The **Threads** window:
  This is stacked below the Terminal window.
  It lists the threads in the current target.
  The nearest equivalent in GDB is `info threads`.
* The **Time** window:
  This is stacked below the Terminal window.
  This lists the events and snapshots taken of the current target.
* The **Static Mappings** window:
  This is stacked below the Terminal window.
  It lists mappings from the current trace (dynamic address ranges) to program databases (static address ranges).
  Generally, this list is populated automatically, but may still be useful for diagnostics or manual mapping.
* The **Stack** window:
  This is on the bottom left.
  It lists the stack frames for the current thread.
  The equivalent in GDB is `backtrace`.
* The **Watches** window:
  This is stacked below the Stack window &mdash; pun not intended.
  It manages current watches.
  These are *not* watchpoints, but rather expressions or variables whose values you wish to display.
  To manage watchpoints, use the Breakpoints window or the Terminal.
  The nearest equivalent in GDB is `display`.
* The **Regions** window:
  This is stacked below the Stack window.
  It lists memory regions for the current target.
  It differs from the Modules window, since this includes not only image-backed regions but other memory regions, e.g., stacks and heaps.
  The equivalent in GDB is `info proc mappings`.
* The **Model** window:
  The back-end debugger populates an object model in the trace database.
  It is from this model that many other windows derive their contents: Threads, Modules, Regions, etc.
  This window presents that model and provides access to generic actions on the contained objects.
  It is generally more capable, though less integrated, than the other parts of the GUI, but not quite as capable as the Terminal.
  For some advanced use cases, where Ghidra does not yet provide built-in actions, it is essential.

## Controlling the Target

The control buttons are all located on the global toolbar.
Start by pressing the ![step into](images/stepinto.png) **Step Into** button.
Notice that the Dynamic Listing moves forward a single instruction each time you press it.
Also notice that the Static Listing moves with the Dynamic Listing.
You may navigate in either listing, and so long as there is a corresponding location in the other, the two will stay synchronized.
You may also open the Decompiler just as you would in the CodeBrowser, and it will stay in sync too.
**TIP**: If you get lost in memory, you can seek back to the program counter by double-clicking "pc = ..." in the top right of the listing.

When you have clicked ![step into](images/stepinto.png) **Step Into** a sufficient number of times, you should end up in a subroutine.
You can click ![step out](images/stepout.png) **Step Out** to leave the subroutine.
Note that the target is allowed to execute until it returns from the subroutine; it does not skip out of it.
Now, click ![step over](images/stepover.png) **Step Over** until you reach another `CALL` instruction.
Notice that when you click ![step over](images/stepover.png) **Step Over** again, it will not descend into the subroutine.
Instead, the target is allowed to execute the entire subroutine before stopping again &mdash; after the `CALL` instruction.

If you prefer, you may use the GDB commands from the Terminal instead of the buttons.
Try `si` and/or `ni`.
You can also pass arguments which is not possible with the buttons, e.g. `si 10` to step 10 instructions in one command.

If you need to terminate the target you should use the ![disconnect](images/disconnect.png) **Disconnect** button rather than the **Kill** button, in general.
Otherwise, each launch will create a new connection, and you will end up with several stale connections.
Additionally, if your target exits or otherwise terminates on its own, you will get a stale connection.
Use the Connections window to clean such connections up, or just type `quit` into the session's Terminal.
The re-use of connections and/or the use of multiple concurrent connections is *not* covered in this course.

## Troubleshooting

### The listings are not in sync, i.e., they do not move together.

First, check that synchronization is enabled.
This is the default behavior, but, still, check it first.
In the top-right of the Dynamic Listing is its local drop-down menu.
Click it and check that **Auto-Sync Cursor with Static Listing** is selected.

If that does not work, check the top-left label of the Dynamic Listing to see what module you are in.
Also check the Debug Console window.
If you are in a system library, e.g., `ld-linux`, then this is the expected behavior.
You may optionally import it, as suggested by the Debug Console, but this is covered later.
You may also try typing into the Terminal, *one command at a time*, checking for errors after each:

```gdb
break main
continue
```

That should get you from the system entry into the target's `main` routine, assuming it has one.
Next time you launch, check the configuration and change **Run Command** to "start", not "starti".

If you are not in a system library, then check the Modules window to see if `termmines` is listed.
If so, it seems the module mapper failed to realize that module is the current program.
Right-click the module and select **Map to termmines**.
Confirm the dialog.
If `termmines` is not listed, then your version of GDB may not be supported.
If you file a bug report, please include your GDB version, Linux distribution, and/or other platform details.

### The listings seem to move together, but their contents differ.

There is probably a discrepancy between the version you imported and the version you launched.
This should not happen with `termmines`, but perhaps you re-ran `make` between importing and launching?
For other system libraries, this could happen if you or an administrator applied system updates since you imported.
You probably need to re-import the affected module image(s).
If this happens to you in practice, and you have substantial investment in the old program database, consider using the Version Tracker to port your knowledge to the new database.

### There is no step button.

This can happen if the Control Mode is set to **Control Trace**.
Perhaps you played with the Time window?
The Control Mode drop-down is leftmost in the "Control" group, immediately right of the **Launch** and **Emulate** buttons.
Its icon differs for each mode.
Change it back to **Control Target**.

### I can step, but I don't see the effects in the Terminal window.

This can happen if the Control Mode is set to **Control Emulator**.
See the above heading about Control Mode.
Change it back to **Control Target**.

### The Step buttons are grayed out.

The target has likely terminated, or you have not selected a thread.
Check the Threads window or the Model window.
If it is empty, re-launch, and perhaps look at the Troubleshooting section in [Getting Started](A1-GettingStarted.md)

## Exercise: Step Around

If you were not already following along with an instructor, then try some of the stepping buttons.
One of the first subroutines called in `termmines` parses command-line arguments.
Try stepping until you have entered that subroutine.
**TIP**: Use the Decompiler to help you recognize when you have entered the command-line parsing subroutine.
Alternatively, use the Static Listing and Decompiler to identify the parsing subroutine (as you would in the CodeBrowser), and then use the **Step** buttons to drive the target into it.
