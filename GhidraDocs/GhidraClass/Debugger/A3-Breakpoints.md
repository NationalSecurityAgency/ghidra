
# Using Breakpoints

This module assumes you know how to launch `termmines` in Ghidra using GDB and know where to find the basic Debugger GUI components.
If not, please refer to the previous modules.

This module will address the Breakpoints window in more depth.
While the breakpoint manager is able to deal with a system of targets, we will only deal with a single target at a time.

## Breakpoints

Most likely, this window is empty if you have been following the lesson.

![The breakpoints window](images/Breakpoints_EmptyAfterLaunch.png)

From here, you can toggle and delete existing breakpoints.
There are several ways to set a new breakpoint:

1. From any static or dynamic listing window, including Disassembly, Memory/Hex, and the Decompiler, right-click and select ![set breakpoint](images/breakpoint-enable.png) Set Breakpoint, press **`K`** on the keyboard, or double-click the margin.
1. From the Terminal window, use the GDB command, e.g., `break main`.

The advantage of using the listings is that you can quickly set a breakpoint at any address.
The advantage of using the Terminal window is that you can specify something other than an address.
Often, those specifications still resolve to addresses, and Ghidra will display them.
Ghidra will memorize breakpoints by recording them as special bookmarks in the program database.
There is some iconography to communicate the various states of a breakpoint.
When all is well and normal, you should only see enabled ![enabled breakpoint](images/breakpoint-enable.png) and disabled ![disabled breakpoint](images/breakpoint-disable.png) breakpoints.
If the target is terminated (or not launched yet), you may also see ineffective ![ineffective breakpoint](images/breakpoint-enable-ineff.png) breakpoints.

## Examining Minesweeper Board Setup

Suppose we want to cheat at `termmines`.
We might like to understand how the mines are placed.
Knowing that the mines are placed randomly, we might hypothesize that it is using the `srand` and `rand` functions from the C standard library.
While we can test that hypothesis by examining the imports statically, we might also like to record some actual values, so we will approach this dynamically.
(This is the Debugger course, after all.)
The breakpoint on `srand` will allow us to capture the random seed.
The breakpoint on `rand` will help us find the algorithm that places the mines.

### Set the Breakpoints

In the Terminal, type the GDB commands to set breakpoints on `srand` and `rand`:

```gdb
break srand
break rand
```

The breakpoint window should now be updated:

![Populated breakpoints window](images/Breakpoints_PopAfterSRandRand.png)

For a single target, the lower panel of the Breakpoints window does not add much information, but it does have some.
We will start with the top panel.
This lists the *logical* breakpoints, preferring static addresses.

* The left-most column **State** indicates the breakpoint's state.
  Here, we see the inconsistent ![inconsistent](images/breakpoint-overlay-inconsistent.png) overlay, because Ghidra cannot save the breakpoint without a program database.
  That is because `srand` and `rand` are in a different module, and we have not yet imported it into Ghidra.
* The next column **Name** is the name of the breakpoint.
  This is for informational purposes only.
  You can rename a breakpoint however you like, and it will have no effect on the target nor back-end debugger.
* The next column **Address** gives the address of the breakpoint.
  Notice that the addresses were resolved, even though the breakpoints were specified by symbol.
  Typically, this is the *static* address of the breakpoint; however, if the module image is not imported, yet, this will be the *dynamic* address, subject to relocation or ASLR.
* The next column **Image** gives the name of the program database containing the breakpoint.
  Again, because the module has not been imported yet, this column is blank.
* The next column **Length** gives the length of the breakpoint.
  In GDB, this generally applies to watchpoints only.
* The next column **Kinds** gives the kinds of breakpoint.
  Most breakpoints are software execution breakpoints, indicated by "SW_EXECUTE."
  That is, they are implemented by patching the target's memory with a special instruction that traps execution &mdash; `INT3` on x86.
  There are also hardware execution breakpoints indicated by "HW_EXECUTE," and access breakpoints indicated by "HW_READ" and/or "HW_WRITE".
  **NOTE**: GDB would call access breakpoints *watchpoints*.
  An advantage to software breakpoints is that you can have a practically unlimited number of them. Some disadvantages are they can be detected easily, and they are limited to execution breakpoints.
* The next column **Locations** counts the number of locations for the breakpoint.
  For a single-target session, this is most likely 1.
* The final column **Sleigh** is only applicable to the emulator.
  It indicates that the breakpoint's behavior has been customized with Sleigh code.
  This is covered in [Emulation](B2-Emulation.md).

Now, we move to the bottom panel.
This lists the breakpoint locations, as reported by the back-end debugger(s).
The State, Address, and Sleigh columns are the same as the top, but for the individual *dynamic* addresses.

* The **Name** column is the name as designated by the back-end.
* The **Trace** column indicates which target contains the location.
  The text here should match one of the tabs from the Dynamic Listing panel.
* The **Comment** column is a user-defined comment.
  Its default value is the specification that generated it, e.g., `srand`.

### Toggling the Breakpoints

While there is no need to toggle the breakpoints right now, it is a good time to demonstrate the feature.
There are several ways to toggle a breakpoint:

1. In any listing, as in setting a breakpoint, right-click and select a toggle action, press **`K`** on the keyboard, or double-click its icon in the margin.
1. From the Model window, expand the *Breakpoints* node and double-click a breakpoint, or select one with the keyboard and press **`ENTER`**.
1. From the Breakpoints window, single-click the breakpoint's status icon, right-click an entry and select a toggle action, or create a selection and use a toggling action from the local toolbar.
   Either panel works, but the top panel is preferred to keep the breakpoints consistent.
   The local toolbar also has actions for toggling all breakpoints in the session.
1. From the Terminal window, use the GDB commands, e.g., `disable 2`.

Practice toggling them.
Notice that no matter how you toggle the breakpoints, the display updates.
You might also type `info break` into the Terminal to confirm the effect of toggling breakpoints in the GUI.
When you are finished, ensure both breakpoints are enabled.

**NOTE**: In all parts of the GUI, except the Model window, Ghidra prefers to toggle breakpoint locations.
Without getting into details, this is the second level down of breakpoints shown in the Model tree.
If you set a breakpoint, and GDB calls this breakpoint 2, then you toggle it in the listing, Ghidra will toggle, e.g., breakpoint *location* 2.1, not the breakpoint *specification* 2.
If you disable breakpoint 2 using the Model or Terminal window, it may become impossible to toggle the breakpoint in the Listing or Breakpoints windows.
If you find your session in this condition, just re-enable the troublesome breakpoints in the Model or Terminal window.

### Importing `libc`

While the Debugger can operate without importing external modules, it generally works better when you have.
The symbols `srand` and `rand` are in `libc`.
If you would like to save the breakpoints we placed on them, you must import the module.
You could do this in the usual manner, but the Debugger offers a convenient way to import missing modules.

1. Navigate to a dynamic address that would be mapped to the missing module.
   For our scenario, the easiest way to do that is to double-click an address in the Breakpoints window.
   Either one points somewhere in `libc`.
1. Check the Debug Console window for a note about the missing module:

   ![Missing module note in the debug console](images/Breakpoints_MissingModuleNote.png)

1. Click the import button &mdash; leftmost of the remedial actions.
   It will display a file browser pointed at the library file.
1. Proceed with the import and initial analysis as you would in the CodeBrowser.

Once imported, the Breakpoints window should update to reflect the static addresses, the breakpoints should become consistent, and the Static Listing should now be synchronized when navigating within `libc`.
**NOTE**: Ghidra has not automatically disassembled the dynamic listing, because the program counter has not actually landed there, yet.

![The debugger tool with breakpoints synchronized after importing libc](images/Breakpoints_SyncedAfterImportLibC.png)

#### Troubleshooting

If it seems nothing has changed, except now you have a second program database open, then the new module may not be successfully mapped.

1. Re-check the Debug Console window and verify the note has been removed.
1. If not, it might be because the module is symlinked in the file system, so the name of the module and the name of the program database do not match.
1. Ensure that `libc` is the current program (tab) in the Static Listing.
1. In the Modules window, right-click on `libc`, and select **Map Module to libc**. (Names and titles will likely differ.)

### Capturing the Random Seed

We can now allow `termmines` to execute, expecting it to hit the `srand` breakpoint first.
Click ![resume](images/resume.png) Resume.
If all goes well, the target should break at `srand`.
If you have never written code that uses `srand` before, you should briefly read its manual page.
It takes a single parameter, the desired seed.
That parameter contains the seed this very moment!
We can then examine the value of the seed by hovering over `param_1` in the decompiler.

![Seed value in decompiler hover](images/Breakpoints_SeedValueAfterBreakSRand.png)

We will cover other ways to examine memory and registers in the [Machine State](A4-MachineState.md) module.
We have contrived `termmines` so that its random seed will always start with `0x5eed____`.
If you see that in the value displayed, then you have successfully recovered the seed.
This seed will be used in an optional exercise at the end of this module.
You might write it down; however, if you re-launch `termmines` between now and then, you will have a different seed.

### Locating the Mine Placement Algorithm

Press ![resume](images/resume.png) Resume again.
This time, the target should break at `rand`.
We are not interested in the `rand` function itself, but rather how the placement algorithm is using it.
Press ![step out](images/stepout.png) Step Out to allow the target to return from `rand`.
If you still have the Decompiler up, you should be in a code block resembling:

```c {.numberLines}
while (iVar2 = DAT_00604164, iVar1 = DAT_00604160, iVar10 < _DAT_00604168) {
  iVar3 = rand();
  iVar2 = DAT_00604164;
  iVar11 = rand();
  lVar7 = (long)(iVar11 % iVar2 + 1) * 0x20 + (long)(iVar3 % iVar1 + 1);
  bVar14 = *(byte *)((long)&DAT_00604160 + lVar7 + 0x1c);
  if (-1 < (char)bVar14) {
    iVar10 = iVar10 + 1;
    *(byte *)((long)&DAT_00604160 + lVar7 + 0x1c) = bVar14 | 0x80;
  }
}
```

If you are thinking, "I could have just found `rand` in the symbol table and followed its XRefs," you are correct.
However, it is useful to use a dynamic debugging session to drive your analysis chronologically through execution of the target, even if much of that analysis is still static.
The advantages of a dynamic session along side static analysis should become more apparent as you progress through this course.

### Exercise: Diagram the Mines

You goal is to capture the location of all the mines.
You will probably want to disable the breakpoints on `rand` and `srand` for now.
Devise a strategy using breakpoints and the control buttons (Step, Resume, etc.) so that you can observe the location of each mine.
Use pen and paper to draw a diagram of the board, and mark the location of each mine as you observe the algorithm placing it.
There should only be 10 mines in Beginner mode.
Once the mines are placed, press ![resume](images/resume.png) Resume.
Check you work by winning the game.
Alternatively, you can intentionally lose to have the game reveal the mines.

#### Troubleshooting

You may find that running both GDB and `termmines` in the same Terminal makes viewing the game board difficult.
The next time you launch, be sure to use the **Configure and Launch** sub-menu, then enable the **Inferior TTY** option.
This should start two Terminals, one with GDB and a second dedicated to `termmines`.
The game board will no longer be corrupted by GDB's prompts and diagnostics.
You will probably want to undock the `termmines` Terminal and resize it to fit the board.

### Optional Exercise: Replicate the Boards (Forward Engineering)

You will need a C development environment for this exercise.
Because, as we have now confirmed, `termmines` is importing its random number generator from the system, we can write a program that uses that same generator.
Further, because we can capture the seed, and we know the placement algorithm, we can perfectly replicate the sequence of game boards for any `termmines` session.

Write a program that takes a seed from the user and prints a diagram of the first game board with the mines indicated.
Optionally, have it print each subsequent game board when the user presses **ENTER**.
Check your work by re-launching `termmines`, capturing its seed, inputting it into your program, and then winning the game.
Optionally, win 2 more games in the same session.
