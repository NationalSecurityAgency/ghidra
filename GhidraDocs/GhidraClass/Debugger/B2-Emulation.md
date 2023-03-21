
# Emulation

Emulation is a bit of a loaded term, unfortunately.
Most of the confusion deals with the scope of the emulated target.
Do you just need to step through a few instructions, or a whole function?
Do you need to include external modules?
Do you need to simulate system calls?
Do you need to simulate connected devices?
Most of Ghidra's GUI-accessible emulation features focus on the smaller scope, though it does provide programming interfaces for advanced users to extend that scope.
Those more advanced features are covered in [Modeling](B4-Modeling.md).

This module assumes you have completed the Beginner portion of this course.

## P-code Emulation and Caveats

Ghidra's emulator uses the same p-code as is used by the decompiler.
P-code describes the semantics of each instruction by constructing a sequence of p-code operations.
The p-code specifications for most of Ghidra's languages were designed with decompilation, not necessarily emulation, in mind.
While in most cases, p-code for decompilation suffices for emulation, there are cases where design decisions were made, e.g., to keep decompiler output simple, that makes them less suitable for emulation.
This may manifest, e.g., in an excess of user-defined p-code ops, or *userops*.
The [Modeling](B4-Modeling.md) module discusses ways to implement or stub those userops in the emulator.
Some processor modules provide those stubs "out of the box."
If the emulator ever halts with an "unimplemented userop" message, then you have run into this problem.

## Use Cases

As already hinted at the start of this module, there are several use cases for emulation, and Ghidra tries to meet these cases by integrating emulation into the Debugger UI.
Some of the use cases accessible from the UI are:

* Extrapolation and interpolation of a live target.
* Emulation of a program image.
* P-code semantics debugging.

We will explore each case with a tutorial and exercise.

## Extrapolation and Interpolation

This is perhaps the easiest use case, assuming you already have started a live session.
*Extrapolation* is predicting execution of the target into the future, without allowing the actual target to execute.
Instead, we will allow an emulator to step forward, while reading its initial state from the live target.
This allows you, e.g., to experiment with various patches, or to force execution down a certain path.
If you devise a patch, you can then apply it the live target and allow it to execute for real.
*Interpolation* is similar, but from a snapshot that is in the past.
It can help answer the question, "How did I get here?"
It is more limited, because missing state for snapshots in the past cannot be recovered.

In this tutorial, we will examine the command-line argument parser in `termmines`.

1. Launch `termmines` using GDB in the Ghidra Debugger.
1. If you have not already, do a bit of static analysis to identify the argument parsing function.
   It should be the first function called by `main`.
1. Use a breakpoint to interrupt the live target when it enters this function.
1. Change the "Control mode" drop-down to "Control Emulator."
1. Click ![step into button](images/stepinto.png) Step Into to step the emulator forward.
1. Click ![skip over button](images/skipover.png) Skip Over and ![step back button](images/stepback.png) Step Back to experiment with different execution paths.

About those two new actions:

* ![skip over button](images/skipover.png) **Skip Over**:
  Step the current thread by skipping one instruction.
* ![step back button](images/stepback.png) **Step Back**:
  Step the current thread backward one instruction, or undo an emulated skip or patch.

Try to get the program counter onto the call to `exit(-1)` using only those three step buttons.

You should see things behave more or less the same as they would if it were the live target.
The main exceptions are the Objects and Interpreter windows.
Those always display the state of the live target, as they are unaware of the emulator, and their sole purpose is to interact with the live target.
You can make changes to the emulator's machine state, set breakpoints, etc., just as you would in "Control Target" mode.
**NOTE**: You may see Ghidra interact with the target, despite being in "Control Emulator" mode, because Ghidra lazily initializes the emulator's state.
If the emulated target reads a variable that Ghidra has not yet captured into the current snapshot, Ghidra will read that variable from the live target, capture it, and provide its value to the emulator.

### Stepping Schedules

If you had not noticed before, the subtitle of the Threads window gives the current snapshot number.
If you have stepped in the emulator, it will also contain the sequence of steps emulated.
Recall the *time* element of the Debugger's "coordinates."
(See the [Navigation](A5-Navigation.md) module if you need a refresher.)
The time element, called the *schedule*, consists of both the current snapshot and the sequence of steps to emulate.
The subtitle displays that schedule.
If you have done any patching of the emulator's state, you may notice some more complicated "steps" in the schedule.
The syntax is:

* *Schedule* &rarr; *Snapshot* \[ `:` \[ *Step* ( `;` *Step* ) \* \] \[ `.` *Step* ( `;` *Step* ) \* \] \]
* *Step* &rarr; [ `t` *Id* `-` ] ( *Tick* | *Skip* | *Patch* )
* *Tick* &rarr; *Count*
* *Skip* &rarr; `s` *Count*
* *Patch* &rarr; `{` *SleighStmt* `}`

In essence, the schedule is the starting snapshot, followed by zero or more machine-instruction steps followed by zero or more p-code-operation steps.
Each step is optionally preceded by a thread id.
If omitted, the thread id is the same as the previous step.
If the first step has no thread id, it applies to the snapshot's event thread.
A plain number indicates the number of instructions or operations to execute.
An `s` prefix indicates skip instead of execute.
Curly braces specify a patch using a single Sleigh statement.
Here are some examples:

* `0` &mdash; The first snapshot in the trace.
* `3` &mdash; Snapshot number 3.
* `3:10` &mdash; Emulate 10 machine instructions on the event thread, starting at snapshot 3.
* `3:t1-10` &mdash; Same as above, but on the second thread rather than the event thread.
* `3:10;t1-10` &mdash; Start at snapshot 3. Step the event thread 10 instructions. Step the second thread 10 instructions.
* `3:10.4` &mdash; Start at snapshot 3. Step the event thread 10 instructions then 4 p-code ops.
* `3:{RAX=0x1234};10` &mdash; Start at snapshot 3. Override RAX with 0x1234, then step 10 instructions.

The explication of schedules allows Ghidra to cache emulated machine states and manage its emulators internally.
You can have Ghidra recall or generate the machine state for any schedule by pressing **Ctrl-G** or using **Debugger &rarr; Go To Time** in the menus.

Assuming you got the program counter onto `exit(-1)` earlier:

1. Write down the current schedule.
1. Change back to "Control Target" mode.
   Ghidra will navigate back to the current snapshot, so PC will match the live target.
1. Press **Ctrl-G** and type or paste the schedule in, and click OK.
   The program counter should be restored to `exit(-1)`.

**NOTE**: The thread IDs used in schedules are internal to the current trace database.
Most likely, they *do not* correspond to the thread IDs assigned by the back-end debugger.

### Exercise: Demonstrate the Cell Numbers

The board setup routine in `termmines` first places mines randomly and then, for each empty cell, counts the number of neighboring cells with mines.
In this exercise, you will use extrapolation to experiment and devise a patch to demonstrate all possible counts of neighboring mines:

1. Run `termmines` in a proper terminal and attach to it.
1. Use a breakpoint to trap it at the point where it has placed mines, but before it has counted the neighboring cells with mines.
   (Use **Shift-R** in `termmines` to reset the game.)
1. Use the emulator to extrapolate forward and begin understanding how the algorithm works.
1. Move the mines by patching the board to demonstrate every number of neighboring mines.
   That is, when the board is revealed at the end of the game, all the numbers 1 through 8 should appear somewhere.
1. Use extrapolation to debug and test your patch.
1. Once you have devised your patch, apply it to the live target.
   (Copy-Paste is probably the easiest way to transfer the state from emulator to target.)

## Emulating a Program Image

This use case allows you to load "any" Ghidra program database into the emulator, without a back-end debugger, host environment, or other dependencies.
The result and efficacy of this method depends greatly on what is captured in the program database.
When Ghidra imports an ELF file, it simulates the OS's loader, but only to a degree:
It places each section at its load memory address, it applies relocation fixups, etc.
The resulting program database is suitable for emulating that image, but in relative isolation.
It is probably not possible to load a library module into that same database nor into the same emulator and expect proper linkage.
Ghidra's loaders often "fix up" references to external symbols by allocating a special `EXTERNAL` block, and placing the external symbols there.
There is (currently) no means to re-fix up.
If, however, you import a firmware image for an embedded device, or a memory dump of a process, then the image may already have all the code and linkage necessary.

It is too tedious to categorize every possible situation and failure mode here.
When you encounter an error, you should diagnose it with particular attention to the contents of your program image, and how it expects to interact with its environment: the host system, connected hardware, etc.
The UI has some facilities to stub out dependencies, but if you find yourself creating and applying an extensive suite of stubs, you may want to consider [Modeling](B4-Modeling.md).
This allows you to code your stubs into a library, facilitating re-use and repeatability.

Emulation need not start at the image's designated entry point.
In this tutorial, we will examine the command-line argument parsing routine.

1. Ensure you have no active targets in the Debugger, but have `termmines` open in the Static listing.
1. Go to the entry of the command-line argument parsing function.
1. Right-click its first instruction and select **Emulate Program in New Trace**.

This will map the program into a new trace.
Technically, it is not actually loaded into an emulator, yet, because Ghidra allocates and caches emulators as needed.
Instead, what you have is a single-snapshot trace without a live target.
The initial state is snapshot 0, and emulation is started by navigating to a schedule, just like in extrapolation.
You might be unnerved by the apparently empty and stale Dynamic listing:

![Stale listing upon starting pure emulation](images/Emulation_LazyStaleListing.png)

This is perhaps more a matter of preference, but by default, Ghidra will only populate the Dynamic listing with state initialized by the emulator itself.
When the emulator reads, it will "read through" uninitialized state by reading the mapped program image instead.
This spares the loader from having to copy a potentially large program image into the emulator.
In general, you should refer to the Static listing when following the program counter.
If you see contents in the Dynamic listing following the program counter, then you are probably dealing with self-modifying code.

**NOTE**: If you prefer to see the Dynamic listing initialized with the program image, you may select **Load Emulator from Program** from the Auto-Read drop-down button in the Dynamic Listing.
The loading is still done lazily as each page is viewed in the listing pane.
You will want to change this back when debugging a live target!

Because we can easily step back and forth as well as navigate to arbitrary points in time, emulation should feel relatively free of risk; however, the point about stubbing dependencies will become apparent.
If you feel the need to start over, there are two methods:
First, you can end the emulation session and restart it.
To end the session, in the Threads panel, right-click the "Emulate termmines" tab and select Close.
You can then restart by right-clicking the first instruction as before.
Second, you can use **Ctrl-G** to go to snapshot 0.
This method is not as clean as the first, because the trace will retain its scratch snapshots.

Press ![resume button](images/resume.png) Resume to let the emulator run until it crashes.
It should crash pretty quickly and without much ceremony:

![Listing after crashing](images/Emulation_ListingAfterResume.png)

In this case, the clearest indication that something has gone wrong is in the top-right of the Dynamic listing.
Recall that the location label is displayed in red when the program counter points outside of mapped memory.
Presumably, the crash was caused by the instruction to be executed next.
To get details about the error, press ![step into button](images/stepinto.png) Step Into.
This should display an error dialog with a full trace of the crash.
In this case, it should be an instruction decode error.
When the emulator reads uninitialized memory, it will get stale 0s; however, when the emulator tries to *execute* uninitialized memory, it will crash.
Most likely, the target called an external function, causing the program counter to land in the fake `EXTERNAL` block.

To diagnose the crash, press ![step back button](images/stepback.png) Step Back.
After a couple steps back, you should be able to confirm our hypothesis: we got here through a call to the external function `printf`.
You can continue stepping back until you find the decision point that took us down this path.
You should notice it was because `param_1` was 0.
The decompiler can help you recognize that at a glance, but you will still want to use the disassembly to get at precisely the deciding instruction.
The `JZ` (or other conditional jump) is too late; you need to step back to the `TEST EDI,EDI` (or similar) instruction.
(This may, ironically, be the first instruction of the function.)
In the System V AMD64 ABI (Linux x86-64 calling conventions) `RDI` is used to pass the first parameter.
You can hover your mouse over `param_1` in the Decompiler, and it will tell you the location is `EDI:4`, and that its current value is a stale 0.

### Initializing Other State

We had just started executing the target function arbitrarily.
Ghidra takes care of a minimal bit of initialization of the trace to start emulation.
Namely, it maps the image to its preferred base.
It allocates space for the main thread's stack and initializes the stack pointer.
Finally, it initializes the program counter.

It is still up to you to initialize any other state, especially the function's parameters.
Clearly, we will need to initialize `param_1`.
We may need to do a little static analysis around the call to this function to understand what those parameters are, but you could probably make an educated guess:
`param_1` is `argc` and `param_2` is `argv`.
We might as well initialize both.
Luckily, we have plenty of memory, and given the small scope of emulation, we can probably place the strings for `argv` wherever we would like.

You may prefer to apply patches to the trace database or to the emulator.
The advantage to patching in the emulator is that once you have completed your experiments, you can readily see all of the steps that got you to the current machine state, including all patches.
The disadvantage is that if you have extensive patches, they will pollute the stepping schedule, and things can get unwieldy.

Alternatively, you can perform the patches in the trace.
When you launched the emulated target, all Ghidra really did was initialize a trace database.
The advantage to patching the trace is that once you have completed your experiments, you will have your initial state captured in a trace snapshot.
The disadvantage is that you will need to remember to invalidate the emulator cache any time you change the initial state.
For this tutorial, we will perform the patches in the emulator.

**NOTE**: If you wish to try patching the trace, then change to "Control Trace" mode and use the "Navigate backward one snapshot" control action that appears, so that you are patching the initial state, and not a scratch snapshot.
Scratch snapshots are ephemeral snapshots in the trace used to display emulated state.
Changes to these snapshots will affect the display, but will not affect subsequent emulation.
If your current schedule includes any steps, then "Control Trace" is patching a scratch snapshot.

Now, we will manually "allocate" memory for `argv`.
Luckily, Ghidra allocated 16K of stack space for us!
The target function should not need a full 16K, so we will allocate the lowest addresses of the stack region for our command-line arguments.
If you prefer, you may use the **Add Region** action in the Regions window to manually fabricate a heap region, instead.
In the Regions window, filter for "stack" and take note of the start address, e.g., `00001000`.
We will use the Watches window to perform our patching, though we will also use the Dynamic listing to double check.
Add the following watches:

* `RSP` &mdash; to confirm the stack pointer is far from `argv`.
* `RDI` &mdash; the location of `param_1`, i.e., `argc`.
* `RSI` &mdash; the location of `param_2`, i.e., `argv`.

To start, we will just try to return successfully from the parser.
From the behavior we have observed, it requires at least `argv[0]` to be present.
Conventionally, this is the name of the binary as it was invoked from the shell, i.e., `termmines`.
There are few reasons a UNIX program might want to examine this "argument."
First, if the binary actually implements many commands, like `busybox` does, then that binary needs to know the actual command.
Second, if the binary needs to print usage information, it may like to echo back the actual invocation.
It is possible we may only need to initialize `argc`, since the parser may not actually *use* the value of `argv[0]`.

Use the Watches window to set `RDI` to 1, then click ![resume button](images/resume.png) Resume.
Like before, the emulator will crash, but this time you should see "pc = 00000000" in red.
This probably indicates success.
In the Threads window, you should see a schedule similar to `0:t0-{RDI=0x1);t0-16`.
This tells us we first patched RDI, then emulated 16 machine instructions before crashing.
When the parser function returned, it probably read a stale 0 as the return address, so we would expect a decode error at `00000000`.
Step backward once to confirm this hypothesis.

### Stubbing External Calls

For this tutorial, we will set the skill level to Advanced by patching in actual command-line arguments.
This continues our lesson in state initialization, but we may also need to stub some external calls, e.g., to `strnlen` and `strcmp`.
We will need to pass in `termmines -s Advanced`, which is three arguments.
Use **Ctrl-G** to go back to snapshot 0, and add the following watches:

* `*:8 (RSI + 0)` &mdash; the address of the first argument, i.e., `argv[0]`.
* `*:30 (*:8 (RSI + 0))` with type `TerminatedCString` &mdash; at most 30 characters of the first argument.
* `*:8 (RSI + 8)` &mdash; `argv[1]`
* `*:30 (*:8 (RSI + 8))` with type `TerminatedCString` &mdash; contents of `argv[1]`
* `*:8 (RSI + 16)` &mdash; `argv[2]`
* `*:30 (*:8 (RSI + 16))` with type `TerminatedCString` &mdash; contents of `argv[2]`

![Watches for patching command-line arguments](images/Emulation_WatchesForCmdline.png)

This will generate an extensive list of patch steps, so you may prefer to patch the trace in this case.
Set `RDI` to 3.
Notice that `argv[0]` is supposedly allocated at `00000000` according to the Address column for the watch on `*:8 (RSI + 0)`.
That was determined by the value of `RSI`, which is essentially telling us we need to allocate `argv`, an array of pointers.
We can confirm `RSP` is at the upper end of the stack region, so we allocate `argv` at `00001000`.
To do that, set the value of `RSI` to `0x1000`.
You should see the Address column update for some other watches.
You can double-click any of those addresses to go there in the Dynamic listing.

**NOTE**: You *do not have* to allocate things in a listed region, but if you want to see those things in the Dynamic listing, it is easiest if you allocate them in a listed region.

Now, we need to allocate space for each argument's string.
To ensure we do not collide with the space we have already allocated for `argv`, we should place a data unit in the Dynamic listing.
Double-click the Address `00001000` in the Watches window to go to that address in the Dynamic listing.
Press **P** then **[** (left square bracket) to place a 3-pointer array at that address.
We can now see the next available byte is at `00001018`.
**NOTE**: You might set the Dynamic listing to **Do Not Track**, otherwise it may seek back to the PC every time you patch.

Now that we know where to put `argv[0]`, we need to patch it to `0x0001018`.
This should be the watch on `*:8 (RSI + 0)`.
When you modify the Value column, you can type either bytes (in little-endian order for x86) or the integer value `0x1018`.
That should cause the watch on `*:30 (*:8 (RSI + 0))` to get the address `00001018`.
Using the Repr column, set that watch's value to `"termmines"`.
(The quotes are required.)
Place a string in the Dynamic listing using the **'** (apostrophe) key.
This shows us the next available address is `00001022`, so repeat the process to allocate `argv[1]` and set it to `"-s"`.
Then finally, allocate `argv[2]` and set it to `"Advanced"`.
When you have finished, the Watches pane should look something like this:

![Watches for patching command-line arguments after setting](images/Emulation_WatchesForCmdlineSet.png)

The Dynamic listing should look something like this:

![Listing after setting command-line arguments](images/Emulation_ListingForCmdlineSet.png)

**NOTE**: The placement of data units is not necessary for the emulator to operate; it only cares about the bytes.
However, it is a useful aide in devising, understanding, and diagnosing machine state.

Now, click ![resume button](images/resume.png) Resume, and see where the emulator crashes next.
Depending on your compilation of `termmines`, it may crash after returning, or it may crash trying to call `strnlen` or `strcmp`.
If the program counter is `00000000`, then it returned successfully.
This is unfortunate, because you no longer have motivation to stub external calls.

If the program counter is not `00000000`, then step backward until you get to the `CALL`.
There are at least three techniques for overcoming this.

1. You can skip the `CALL` and patch `RAX` accordingly.
1. You can override the `CALL` instruction using a Sleigh breakpoint.
1. You can override the call target using a Sleigh breakpoint.

#### Skip Technique

The skip technique is simplest, but will need to be performed *every time* that call is encountered.
Press ![skip over button](images/skipover.png) Skip Over, then use the Registers or Watches pane to patch `RAX`.
Then press ![resume button](images/resume.png) Resume.

#### `CALL` Override Technique

Overriding the `CALL` is also fairly simple.
While this will handle every encounter, it will not handle other calls to the same external function.

1. Press **K** in the listing to place a breakpoint on the `CALL` instruction.
1. Now, in the Breakpoints panel, right-click the new breakpoint and select **Set Injection (Emulator)**.
1. This is the fun part: you must now implement the function in Sleigh, or at least stub it well enough for this particular call.

Supposing this is a call to `strnlen`, you could implement it as:

```sleigh {.numberLines}
RAX = 0;
<loop>
if (*:1 (RDI+RAX) == 0 || RAX >= RSI) goto <exit>;
RAX = RAX + 1;
goto <loop>;
<exit>
emu_skip_decoded();
```

While Sleigh has fairly nice C-like expressions, it unfortunately does not have C-like control structures.
We are essentially writing a for loop.
The System V AMD64 ABI specifies RAX is for the return value, so we can just use it directly as the counter.
RDI points to the string to measure, and RSI gives the maximum length.
We initialize RAX to 0, and then check if the current character is NULL, or the count has exceeded the maximum length.
If so, we are done; if not, we increment RAX and repeat.
Finally, because we are *replacing* the semantics of the `CALL` instruction, we tell the emulator to skip the current instruction.

For the complete specification of Sleigh, see the Semantic Section in the [Sleigh documentation](../../../Ghidra/Features/Decompiler/src/main/doc/sleigh.xml).
The emulator adds a few userops:

* `emu_skip_decoded()`: Skip the current instruction.
* `emu_exec_decoded()`: Execute the current instruction.
* `emu_swi()`: Interrupt, as in a breakpoint.

Some control flow is required in the Sleigh injection, otherwise, the emulator may never advance past the current instruction.
An explicit call to `emu_exec_decoded()` allows you to insert logic before and/or after the original instruction; however, if the original instruction branches, then the logic you placed *after* will not be reached.
An explicit call to `emu_skip_decoded()` allows you to omit the original instruction altogether.
It immediately falls through to the next instruction.
The `emu_swi()` userop allows you to maintain breakpoint behavior, perhaps to debug your injection.

After you have written your Sleigh code:

1. Click OK on the Set Injection dialog.
1. In the menus, select **Debugger &rarr; Configure Emulator &rarr; Invalidate Emulator Cache**.
1. Click ![resume button](images/resume.png) Resume.

Stubbing any remaining external calls is left as an exercise.
You are successful when the emulator crashes with `pc = 00000000`.

Clear or disable your breakpoint and invalidate the emulator cache again before proceeding to the next technique.

#### Target Override Technique

The target override technique is most thorough, but also the most involved.
It will handle all calls to the external function, e.g., `strnlen`, no matter the call site.
If the call goes through a program linkage table (PLT), then you are in luck, because the call target will be visible in the Dynamic listing.
The PLT entry usually contains a single `JMP` instruction to the actual `strnlen`.
For real target processes, the `JMP` instruction will transfer control to a lazy linker the first time `strnlen` is called from `termmines`.
The linker then finds `strnlen` and patches the table.
In contrast, the Ghidra loader immediately patches the table to point to a fake `<EXTERNAL>::strnlen` symbol.
The `EXTERNAL` block is not visible in the Dynamic listing, so we will override the `JMP` in the PLT.

The Sleigh code is nearly identical, but we must code an x86 `RET` into it.
Because we allow the `CALL` to execute normally, we must restore the stack.
Furthermore, we must return control back to the caller, just like a real x86 subroutine would.
We also no longer need `emu_skip_decoded()`, because the `RET` will provide the necessary control transfer.

```sleigh {.numberLines}
RAX = 0;
<loop>
if (*:1 (RDI+RAX) == 0 || RAX >= RSI) goto <exit>;
RAX = RAX + 1;
goto <loop>;
<exit>
RIP = *:8 RSP;
RSP = RSP + 8;
return [RIP];
```

Notice that we cannot just write `RET`, but instead must write the Sleigh code to mimic a `RET`.
As with the `CALL` override technique, you must now invalidate the emulator cache and resume.
Stubbing any remaining external functions is left as an exercise.
You are successful when the emulator crashes with `pc = 00000000`.

### Wrapping Up

As you can see, depending on the scope of emulation, and the particulars of the target function, emulating a program image can be quite involved.
Whatever technique you choose, once you have successfully returned from the command-line argument parser, you should check for the expected effects.

In the Static listing, navigate to the variable that stores the board's dimensions.
(Finding that variable is a task in the Beginner portion, but it can be found pretty easily with some manual static analysis.)
In the Dynamic listing, you should notice that the values have changed to reflect the Advanced skill level.

### Optional Exercise: Patch the Placement Algorithm

In this exercise, you will use emulation to devise an assembly patch to `termmines` to change the mine placement algorithm.
Instead of random placement, please have them placed left to right, top to bottom.
We recommend you devise your patch using the Assembler (Patch Instruction action) in the Static listing, then test and debug your patch using the Emulator.
Perhaps patch the Dynamic listing to try quick tweaks before committing them to the Static listing.
Once you have it, export the patched binary and run it in a proper terminal.

## Debugging P-code Semantics

The last use case for emulation we will cover in this course is debugging p-code semantics.
This use case is a bit niche, so we will not cover it too deeply.
It is useful for debugging processor modules.
It is also useful in system modeling, since a lot of that is accomplished using Sleigh p-code.
Perhaps the most useful case related to this module is to debug Sleigh injections.

Ghidra has a dedicated panel for stepping the emulator one p-code operation at a time.
This panel is not included in the default Debugger tool, so it must be configured:

1. If you have not already, open the Debugger tool.
1. In the menus, select **File &rarr; Configure**.
1. Click the "Configure All Plugins" button in the top right of the dialog.
1. Activate the `DebuggerPcodeStepperPlugin`
1. Click OK
1. Click Close

The stepper should appear stacked over the Threads panel in the bottom right.
Yours will probably still be empty, but here is what it looks like populated:

![P-code stepper](images/Emulation_PcodeStepper.png)

To populate it, you will need a session, either emulated or connected to a back-end debugger.
Use the buttons in the local toolbar to step p-code operations.
The first p-code op of any instruction is to decode the instruction.
Once decoded, the p-code listing (left panel) will populate with the ops of the decoded instruction.
If the current instruction is overridden by a Sleigh breakpoint, the listing will populate with the injected ops instead.
You can then step forward and backward within those.
As you step, the other windows that display machine state will update.

In addition to registers and memory, p-code has "unique" variables.
These are temporary variables used only within an instruction's implementation.
They are displayed in the right panel.
The table of variables works similarly to the Registers pane.
The columns are:

* The **Unique** column gives the variable's name and size in bytes.
* The **Bytes** column gives the variable's value in bytes.
* The **Value** column gives the variable's value as an integer, an interpretation of the bytes in the machine's byte order.
* The **Type** column allows you to assign a type. This is ephemeral.
* The **Repr** column gives the variable's value according to the assigned type.

As you step, you may notice the schedule changes.
It is displayed in the stepper's subtitle as well as the Threads panel's subtitle.
P-code stepping is denoted by the portion of the schedule following the dot.
**NOTE**: You cannot mix instruction steps with p-code op steps.
The instruction steps always precede the p-code ops.
If you click Step Into from the global toolbar in the middle of an instruction, the trailing p-code op steps will be removed and replaced with a single instruction step.
In most cases, this intuitively "finishes" the partial instruction.
