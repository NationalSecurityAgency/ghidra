
# Debugger Scripting

This module assumes you have completed the Beginner portion of this course, as well as the Scripting module of the Intermediate course.

As with Ghidra Scripting, the primary use case we consider in this module is automation.
It also permits some one-off analysis of a live target or interacting with the dynamic target.
There are also some extension points useful for [Modeling](B4-Modeling.md) that are easily accessed in scripts for prototyping.

The script development environment is set up exactly the same as it is for the rest of Ghidra.

## The Debugger Scripting API

To create a Debugger script, do as you normally would then append `implements FlatDebuggerAPI` to the script's class declaration, e.g.:

```java {.numberLines}
import ghidra.app.script.GhidraScript;
import ghidra.debug.flatapi.FlatDebuggerAPI;

public class DemoDebuggerScript extends GhidraScript implements FlatDebuggerAPI {
	@Override
	protected void run() throws Exception {
	}
}
```

Technically, the Debugger's "deep" API is accessible to scripts; however, the flat API is preferred for scripting.
Also, the flat API is usually more stable than the deep API.
However, because the dynamic analysis flat API is newer, it may not be as stable as the static analysis flat API.
It is also worth noting that the `FlatDebuggerAPI` interface *adds* the flat API to your script.
The static analysis flat API is still available, and it will manipulate the static portions of the Debugger tool, just as they would in the CodeBrowser tool.
In this tutorial, we will explore reading machine state, setting breakpoints, waiting for conditions, and controlling the target.

## Dumping the Game Board

We will write a script that assumes the current session is for `termmines` and dumps the game board to the console, allowing you to cheat.
You can label your variables however you would like but, for this tutorial, we will assume you have labeled them `width`, `height`, and `cells`.
If you have not already located and labeled these variables, do so now.

### Checking the Target

First, we will do some validation.
Check that we have an active session (trace):

```java {.numberLines}
Trace trace = getCurrentTrace();
if (trace == null) {
	throw new AssertionError("There is no active session");
}
```

Now, check that the current program is `termmines`:

```java {.numberLines}
if (!"termmines".equals(currentProgram.getName())) {
	throw new AssertionError("The current program must be termmines");
}
```

### Checking the Module Map

Now, check that `termmines` is actually part of the current trace.
There is not a great way to do this directly in the flat API, but we are going to need to map some symbols from the `termmines` module, anyway.
In this step, we will both verify that the user has placed the required labels, as well as verify that those symbols can be mapped to the target:

```java {.numberLines}
List<Symbol> widthSyms = getSymbols("width", null);
if (widthSyms.isEmpty()) {
	throw new AssertionError("Symbol 'width' is required");
}
List<Symbol> heightSyms = getSymbols("height", null);
if (heightSyms.isEmpty()) {
	throw new AssertionError("Symbol 'height' is required");
}
List<Symbol> cellsSyms = getSymbols("cells", null);
if (cellsSyms.isEmpty()) {
	throw new AssertionError("Symbol 'cells' is required");
}

Address widthDyn = translateStaticToDynamic(widthSyms.get(0).getAddress());
if (widthDyn == null) {
	throw new AssertionError("Symbol 'width' is not mapped to target");
}
Address heightDyn = translateStaticToDynamic(heightSyms.get(0).getAddress());
if (heightDyn == null) {
	throw new AssertionError("Symbol 'height' is not mapped to target");
}
Address cellsDyn = translateStaticToDynamic(cellsSyms.get(0).getAddress());
if (cellsDyn == null) {
	throw new AssertionError("Symbol 'cells' is not mapped to target");
}
```

The `getSymbols()` method is part of the static flat API, so it returns symbols from the current static listing.
The `translateStaticToDynamic()` is part of the dynamic flat API.
This allows us to locate that symbol in the dynamic context.

### Reading the Data

Now, we want to read the dimensions and the whole board to the trace.
You should know from earlier exercises that the board is allocated 32 cells by 32 cells, so we will want to read at least 1024 bytes.
Note that this will implicitly capture the board to the trace:

```java {.numberLines}
byte[] widthDat = readMemory(widthDyn, 4, monitor);
byte[] heightDat = readMemory(heightDyn, 4, monitor);
byte[] cellsData = readMemory(cellsDyn, 1024, monitor);
```

### Dumping the Board

Beyond this, everything is pretty standard Java / Ghidra scripting.
We will need to do some quick conversion of the bytes to integers, and then we can iterate over the cells and print the mines' locations:

```java {.numberLines}
int width = ByteBuffer.wrap(widthDat).order(ByteOrder.LITTLE_ENDIAN).getInt();
int height = ByteBuffer.wrap(heightDat).order(ByteOrder.LITTLE_ENDIAN).getInt();
for (int y = 0; y < height; y++) {
	for (int x = 0; x < width; x++) {
		if ((cellsData[(y + 1) * 32 + x + 1] & 0x80) == 0x80) {
			println("Mine at (%d,%d)".formatted(x, y));
		}
	}
}
```

### Test the Script

To test, run `termmines` in a proper terminal and attach to it from Ghidra using GDB.
Now, run the script.
Resume and play the game.
Once you win, check that the script output describes the actual board.

### Exercise: Remove the Mines

Write a script that will remove the mines from the board.
**NOTE**: The `writeMemory()` and related methods are all subject to the current control mode.
If the mode is read-only, the script cannot modify the target's machine state using those methods.

## Waiting on / Reacting to Events

Most of the Debugger is implemented using asynchronous event-driven programming.
This will become apparent if you browse any deeper beyond the flat API.
Check the return value carefully.
A method that might intuitively return `void` may actually return `CompletableFuture<Void>`.
Java's completable futures allow you to register callbacks and/or chain additional futures onto them.

However, Ghidra's scripting system provides a dedicated thread for each execution of a script, so it is acceptable to use the `.get()` methods instead, essentially converting to a synchronous style.
Most of the methods in the flat API will do this for you.
See also the flat API's `waitOn()` method.
The most common two methods to use when waiting for a condition is `waitForBreak()` and `flushAsyncPipelines()`.
The first simply waits for the target to enter the STOPPED state.
Once that happens, the framework and UI will get to work interrogating the back-end debugger to update the various displays.
Unfortunately, if a script does not wait for this update to complete, it may be subject to race conditions.
Thus, the second method politely waits for everything else to finish.
Sadly, it may slow your script down.

The general template for waiting on a condition is a bit klunky, but conceptually straightforward:

1. Set up your instrumentation, e.g., breakpoints.
1. Get the target running, and then wait for it to break.
1. Flush the pipelines.
1. Check if the expected conditions are met, esp., that the program counter is where you expect.
1. If the conditions are not met, then let the target run again and repeat.
1. Once the conditions are met, perform the desired actions.
1. Optionally remove your instrumentation and/or let the target run.

### Exercise: Always Win in 0 Seconds

**NOTE**: The solution to this exercise is given as a tutorial below, but give it an honest try before peeking.
If you are not already familiar with Eclipse's searching and discovery features, try pressing **Ctrl-O** twice in the editor for your script.
You should now be able to type patterns, optionally with wildcards, to help you find applicable methods.

Your task is to write a script that will wait for the player to win then patch the machine state, so that the game always prints a score of 0 seconds.
Some gotchas to consider up front:

* You may want to verify and/or correct the target's execution state.
  See `getExecutionState()` and `interrupt()`.
  You will not likely be able to place or toggle breakpoints while the target is running.
* Methods like `writeMemory()` are subject to the current control mode.
  You may want to check and/or correct this at the top of your script.
* If you require the user to mark code locations with a label, note that those labels will likely end up in the containing function's namespace.
  You will need to provide that namespace to `getSymbols()`.
* If you need to set breakpoints, you should try to toggle an existing breakpoint at that location before adding a new one.
  Otherwise, you may generate a pile of breakpoints and/or needlessly increment GDB's breakpoint numbers.

You are successful when you can attach to a running `termmines` and execute your script.
Then, assuming you win the game, the game should award you a score of 0 seconds.
It is OK if you have to re-execute your script after each win.

### Solution: Always Win in 0 Seconds

As in the previous scripting tutorial, we will do some verifications at the top of the script.
Your level of pedantry may vary.

```java {.numberLines}
Trace trace = getCurrentTrace();
if (trace == null) {
	throw new AssertionError("There is no active session");
}

if (!"termmines".equals(currentProgram.getName())) {
	throw new AssertionError("The current program must be termmines");
}

if (getExecutionState(trace).isRunning()) {
	monitor.setMessage("Interrupting target and waiting for STOPPED");
	interrupt();
	waitForBreak(3, TimeUnit.SECONDS);
}
flushAsyncPipelines(trace);

if (!getControlService().getCurrentMode(trace).canEdit(getCurrentDebuggerCoordinates())) {
	throw new AssertionError("Current control mode is read-only");
}
```

The first two blocks check that there is an active target with `termmines` as the current program.
As before, the association of the current program to the current target will be implicitly verified when we map symbols.
The second block will interrupt the target if it is running.
We then allow everything to sync up before checking the control mode.
We could instead change the control mode to **Target w/Edits**, but I prefer to keep the user aware that the script needs to modify target machine state.

Next, we retrieve and map our symbols.
This works pretty much the same as in the previous scripting tutorial, but with attention to the containing function namespace.
The way `termmines` computes the score is to record the start time of the game.
Then, when the player wins, it subtracts the recorded time from the current time.
This script requires the user to label the start time variable `timer`, and to label the instruction that computes the score `reset_timer`.
The function that prints the score must be named `print_win`.

```java {.numberLines}
List<Symbol> timerSyms = getSymbols("timer", null);
if (timerSyms.isEmpty()) {
	throw new AssertionError("Symbol 'timer' is required");
}
List<Function> winFuncs = getGlobalFunctions("print_win");
if (winFuncs.isEmpty()) {
	throw new AssertionError("Function 'print_win' is required");
}
List<Symbol> resetSyms = getSymbols("reset_timer", winFuncs.get(0));
if (resetSyms.isEmpty()) {
	throw new AssertionError("Symbol 'reset_timer' is required");
}

Address timerDyn = translateStaticToDynamic(timerSyms.get(0).getAddress());
if (timerDyn == null) {
	throw new AssertionError("Symbol 'timer' is not mapped to target");
}
Address resetDyn = translateStaticToDynamic(resetSyms.get(0).getAddress());
if (resetDyn == null) {
	throw new AssertionError("Symbol 'reset_timer' is not mapped to target");
}
```

#### Toggling and Setting Breakpoints

The first actual operation we perform on the debug session is to toggle or place a breakpoint on the `reset_timer` label.
The API prefers to specify breakpoints in the static context, but you can do either.
To establish that context, you must use a `ProgramLocation`.
For static context, use the current (static) program as the program.
For dynamic context, use the current (dynamic) trace view as the program &mdash; see `getCurrentView()`.

To avoid creating a pile of breakpoints, we will first attempt to enable an existing breakpoint at the desired location.
Technically, the existing breakpoints may not be execute breakpoints, but we will blindly assume they are.
Again, your level of pedantry may vary.
The `breakpointsEnable` method will return the existing breakpoints, so we can check that and create a new breakpoint, if necessary:

```java {.numberLines}
ProgramLocation breakLoc =
	new ProgramLocation(currentProgram, resetSyms.get(0).getAddress());
Set<LogicalBreakpoint> breaks = breakpointsEnable(breakLoc);
if (breaks == null || breaks.isEmpty()) {
	breakpointSetSoftwareExecute(breakLoc, "reset timer");
}
```

#### Waiting to Hit the Breakpoint

This next loop is quite extensive, but it follows the template given earlier for waiting on conditions.
It is an indefinite loop, so we should check the monitor for cancellation somewhat frequently.
This implies we should use relatively short timeouts in our API calls.
In our case, we just want to confirm that the cause of breaking was hitting our breakpoint.
We do not need to be precise in this check; it suffices to check the program counter:

```java {.numberLines}
while (true) {
	monitor.checkCanceled();

	TargetExecutionState execState = getExecutionState(trace);
	switch (execState) {
		case STOPPED:
			resume();
			break;
		case TERMINATED:
		case INACTIVE:
			throw new AssertionError("Target terminated");
		case ALIVE:
			println(
				"I don't know whether or not the target is running. Please make it RUNNING.");
			break;
		case RUNNING:
			/**
			 * Probably timed out waiting for break. That's fine. Give the player time to
			 * win.
			 */
			break;
		default:
			throw new AssertionError("Unrecognized state: " + execState);
	}
	try {
		monitor.setMessage("Waiting for player to win");
		waitForBreak(1, TimeUnit.SECONDS);
	}
	catch (TimeoutException e) {
		// Give the player time to win.
		continue;
	}
	flushAsyncPipelines(trace);
	Address pc = getProgramCounter();
	println("STOPPED at pc = " + pc);
	if (resetDyn.equals(pc)) {
		break;
	}
}
```

The "center" of this loop is a call to `waitForBreak()`.
This is the simplest primitive for waiting on the target to meet any condition.
Because we expect the user to take more than a second to win the game, we should expect a timeout exception and just keep waiting.
Using a timeout of 1 second ensures we can terminate promptly should the user cancel the script.

Before waiting, we need to make sure the target is running.
Because we could repeat the loop while the target is already running, we should only call `resume()` if the target is stopped.
There are utility methods on `TargetExecutionState` like `isRunning()`, which you might prefer to use.
Here, we exhaustively handle every kind of state using a switch statement, which does make the code a bit verbose.

When the target does break, we first allow the UI to finish interrogating the target.
We can then reliably retrieve and check the program counter.
If the PC matches the dynamic location of `reset_timer`, then the player has won, and we need to reset the start time.

#### Patching the Start Time

When the player has won, this particular compilation of `termmines` first calls `time` to get the current time and moves it into `ECX`.
It then subtracts, using a memory operand, the recorded start time.
There are certainly other strategies, but this script expects the user to label that `SUB` instruction `reset_timer`.
We would like the result of that computation to be 0, so we will simply copy the value of `ECX` over the recorded start time:

```java {.numberLines}
int time = readRegister("ECX").getUnsignedValue().intValue();
if (!writeMemory(timerDyn,
	ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(time).array())) {
	throw new AssertionError("Could not write over timer. Does control mode allow edits?");
}

resume();
```

The final `resume()` simply allows the target to finish printing the score, which ought to be 0 now!

## Learning More

For another demonstration of the flat API, see [DemoDebuggerScript](../../../Ghidra/Debug/Debugger/ghidra_scripts/DemoDebuggerScript.java), or just ask Eclipse for all the implementations of `FlatDebuggerAPI`.
If you want a list of methods with explanations, you should refer to the documentation in the `FlatDebuggerAPI` interface.
