/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.debug.api.target;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import docking.ActionContext;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The interface between the front-end UI and the back-end connector.
 * 
 * <p>
 * Anything the UI might command a target to do must be defined as a method here. Each
 * implementation can then sort out, using context from the UI as appropriate, how best to effect
 * the command using the protocol and resources available on the back-end.
 */
public interface Target {
	long TIMEOUT_MILLIS = 10000;

	/**
	 * A description of a UI action provided by this target.
	 * 
	 * <p>
	 * In most cases, this will generate a menu entry or a toolbar button, but in some cases, it's
	 * just invoked implicitly. Often, the two suppliers are implemented using lambda functions, and
	 * those functions will keep whatever some means of querying UI and/or target context in their
	 * closures.
	 * 
	 * @param display the text to display on UI actions associated with this entry
	 * @param name the name of a common debugger command this action implements
	 * @param details text providing more details, usually displayed in a tool tip
	 * @param requiresPrompt true if invoking the action requires further user interaction
	 * @param enabled a supplier to determine whether an associated action in the UI is enabled.
	 * @param action a function for invoking this action asynchronously
	 */
	record ActionEntry(String display, ActionName name, String details, boolean requiresPrompt,
			BooleanSupplier enabled, Function<Boolean, CompletableFuture<?>> action) {

		/**
		 * Check if this action is currently enabled
		 * 
		 * @return true if enabled
		 */
		public boolean isEnabled() {
			return enabled.getAsBoolean();
		}

		/**
		 * Invoke the action asynchronously, prompting if desired
		 * 
		 * <p>
		 * Note this will impose a timeout of {@value Target#TIMEOUT_MILLIS} milliseconds.
		 * 
		 * @param prompt whether or not to prompt the user for arguments
		 * @return the future result, often {@link Void}
		 */
		public CompletableFuture<?> invokeAsync(boolean prompt) {
			return action.apply(prompt).orTimeout(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		}

		/**
		 * Invoke the action synchronously
		 * 
		 * <p>
		 * To avoid blocking the Swing thread on a remote socket, this method cannot be called on
		 * the Swing thread.
		 * 
		 * @param prompt whether or not to prompt the user for arguments
		 */
		public void run(boolean prompt) {
			get(prompt);
		}

		/**
		 * Invoke the action synchronously, getting its result
		 * 
		 * @param prompt whether or not to prompt the user for arguments
		 * @return the resulting value, if applicable
		 */
		public Object get(boolean prompt) {
			if (Swing.isSwingThread()) {
				throw new AssertionError("Refusing to block the Swing thread. Use a Task.");
			}
			try {
				return invokeAsync(prompt).get();
			}
			catch (InterruptedException | ExecutionException e) {
				throw new RuntimeException(e);
			}
		}

		/**
		 * Check if this action's name is built in
		 * 
		 * @return true if built in.
		 */
		public boolean builtIn() {
			return name != null && name.builtIn();
		}
	}

	/**
	 * Check if the target is still valid
	 * 
	 * @return true if valid
	 */
	boolean isValid();

	/**
	 * Get the trace into which this target is recorded
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the current snapshot key for the target
	 * 
	 * <p>
	 * For most targets, this is the most recently created snapshot.
	 * 
	 * @return the snapshot
	 */
	// TODO: Should this be TraceSchedule getTime()?
	long getSnap();

	/**
	 * Collect all actions that implement the given common debugger command
	 * 
	 * @param name the action name
	 * @param context applicable context from the UI
	 * @return the collected actions
	 */
	Map<String, ActionEntry> collectActions(ActionName name, ActionContext context);

	/**
	 * Get the trace thread that contains the given object
	 * 
	 * @param path the path of the object
	 * @return the thread, or null
	 */
	TraceThread getThreadForSuccessor(TraceObjectKeyPath path);

	/**
	 * Get the execution state of the given thread
	 * 
	 * @param thread the thread
	 * @return the state
	 */
	TargetExecutionState getThreadExecutionState(TraceThread thread);

	/**
	 * Get the trace stack frame that contains the given object
	 * 
	 * @param path the path of the object
	 * @return the stack frame, or null
	 */
	TraceStackFrame getStackFrameForSuccessor(TraceObjectKeyPath path);

	/**
	 * Check if the target supports synchronizing focus
	 * 
	 * @return true if supported
	 */
	boolean isSupportsFocus();

	/**
	 * Get the object that currently has focus on the back end's UI
	 * 
	 * @return the focused object's path, or null
	 */
	TraceObjectKeyPath getFocus();

	/**
	 * @see #activate(DebuggerCoordinates, DebuggerCoordinates)
	 */
	CompletableFuture<Void> activateAsync(DebuggerCoordinates prev, DebuggerCoordinates coords);

	/**
	 * Request that the back end's focus be set to the same as the front end's (Ghidra's) GUI.
	 * 
	 * @param prev the GUI's immediately previous coordinates
	 * @param coords the GUI's current coordinates
	 */
	void activate(DebuggerCoordinates prev, DebuggerCoordinates coords);

	/**
	 * @see #invalidateMemoryCaches()
	 */
	CompletableFuture<Void> invalidateMemoryCachesAsync();

	/**
	 * Invalidate any caches on the target's back end or on the client side of the connection.
	 * 
	 * <p>
	 * In general, back ends should avoid doing any caching. Instead, the front-end will assume
	 * anything marked {@link TraceMemoryState#KNOWN} is up to date. I.e., the trace database acts
	 * as the client-side cache for a live target.
	 * 
	 * <p>
	 * <b>NOTE:</b> This method exists for invalidating model-based target caches. It may be
	 * deprecated and removed, unless it turns out we need this for Trace RMI, too.
	 */
	void invalidateMemoryCaches();

	/**
	 * @see #readMemory(AddressSetView, TaskMonitor)
	 */
	CompletableFuture<Void> readMemoryAsync(AddressSetView set, TaskMonitor monitor);

	/**
	 * Read and capture several ranges of target memory
	 * 
	 * <p>
	 * The target may read more than the requested memory, usually because it will read all pages
	 * containing any portion of the requested set. The target should attempt to read at least the
	 * given memory. To the extent it is successful, it must cause the values to be recorded into
	 * the trace <em>before</em> this method returns. Only if the request is <em>entirely</em>
	 * unsuccessful should this method throw an exception. Otherwise, the failed portions, if any,
	 * should be logged without throwing an exception.
	 * 
	 * @param set the addresses to capture
	 * @param monitor a monitor for displaying task steps
	 * @throws CancelledException if the operation is cancelled
	 */
	void readMemory(AddressSetView set, TaskMonitor monitor) throws CancelledException;

	/**
	 * @see #readMemory(AddressSetView, TaskMonitor)
	 */
	CompletableFuture<Void> writeMemoryAsync(Address address, byte[] data);

	/**
	 * Write data to the target's memory
	 * 
	 * <p>
	 * The target should attempt to write the memory. To the extent it is successful, it must cause
	 * the effects to be recorded into the trace <em>before</em> this method returns. Only if the
	 * request is <em>entirely</em> unsuccessful should this method throw an exception. Otherwise,
	 * the failed portions, if any, should be logged without throwing an exception.
	 * 
	 * @param address the starting address
	 * @param data the bytes to write
	 */
	void writeMemory(Address address, byte[] data);

	/**
	 * @see #readRegisters(TracePlatform, TraceThread, int, Set)
	 */
	CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, Set<Register> registers);

	/**
	 * Read and capture the named target registers for the given platform, thread, and frame.
	 * 
	 * <p>
	 * Target target should read the registers and, to the extent it is successful, cause the values
	 * to be recorded into the trace <em>before</em> this method returns. Only if the request is
	 * <em>entirely</em> unsuccessful should this method throw an exception. Otherwise, the failed
	 * registers, if any, should be logged without throwing an exception.
	 * 
	 * @param platform the platform defining the registers
	 * @param thread the thread whose context contains the register values
	 * @param frame the frame, if applicable, for saved register values. 0 for current values.
	 * @param registers the registers to read
	 */
	void readRegisters(TracePlatform platform, TraceThread thread, int frame,
			Set<Register> registers);

	/**
	 * @see #readRegistersAsync(TracePlatform, TraceThread, int, AddressSetView)
	 */
	CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, AddressSetView guestSet);

	/**
	 * Read and capture the target registers in the given address set.
	 * 
	 * <p>
	 * Aside from how registers are named, this works equivalently to
	 * {@link #readRegisters(TracePlatform, TraceThread, int, Set)}.
	 */
	void readRegisters(TracePlatform platform, TraceThread thread, int frame,
			AddressSetView guestSet);

	/**
	 * @see #writeRegister(TracePlatform, TraceThread, int, RegisterValue)
	 */
	CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, RegisterValue value);

	/**
	 * Write a value to a target register for the given platform, thread, and frame
	 * 
	 * <p>
	 * The target should attempt to write the register. If successful, it must cause the effects to
	 * be recorded into the trace <em>before</em> this method returns. If the request is
	 * unsuccessful, this method throw an exception.
	 * 
	 * @param address the starting address
	 * @param data the bytes to write
	 */
	void writeRegister(TracePlatform platform, TraceThread thread, int frame, RegisterValue value);

	/**
	 * @see #writeRegister(TracePlatform, TraceThread, int, Address, byte[])
	 */
	CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, Address address, byte[] data);

	/**
	 * Write a value to a target register by its address
	 * 
	 * <p>
	 * Aside from how the register is named, this works equivalently to
	 * {@link #writeRegister(TracePlatform, TraceThread, int, RegisterValue)}. The address is the
	 * one defined by Ghidra.
	 */
	void writeRegister(TracePlatform platform, TraceThread thread, int frame, Address address,
			byte[] data);

	/**
	 * Check if a given variable (register or memory) exists on target
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread if a register, the thread whose registers to examine
	 * @param frame the frame level, usually 0.
	 * @param address the address of the variable
	 * @param size the size of the variable. Ignored for memory
	 * @return true if the variable can be mapped to the target
	 */
	boolean isVariableExists(TracePlatform platform, TraceThread thread, int frame, Address address,
			int length);

	/**
	 * @see #writeVariable(TracePlatform, TraceThread, int, Address, byte[])
	 */
	CompletableFuture<Void> writeVariableAsync(TracePlatform platform, TraceThread thread,
			int frame,
			Address address, byte[] data);

	/**
	 * Write a variable (memory or register) of the given thread or the process
	 * 
	 * <p>
	 * This is a convenience for writing target memory or registers, based on address. If the given
	 * address represents a register, this will attempt to map it to a register and write it in the
	 * given thread and frame. If the address is in memory, it will simply delegate to
	 * {@link #writeMemory(Address, byte[])}.
	 * 
	 * @param thread the thread. Ignored (may be null) if address is in memory
	 * @param frameLevel the frame, usually 0. Ignored if address is in memory
	 * @param address the starting address
	 * @param data the value to write
	 */
	void writeVariable(TracePlatform platform, TraceThread thread, int frame, Address address,
			byte[] data);

	/**
	 * Get the kinds of breakpoints supported by the target.
	 * 
	 * @return the set of kinds
	 */
	Set<TraceBreakpointKind> getSupportedBreakpointKinds();

	/**
	 * @see #placeBreakpoint(AddressRange, Set, String, String)
	 */
	CompletableFuture<Void> placeBreakpointAsync(AddressRange range,
			Set<TraceBreakpointKind> kinds, String condition, String commands);

	/**
	 * Place a new breakpoint of the given kind(s) over the given range
	 * 
	 * <p>
	 * If successful, this method must cause the breakpoint to be recorded into the trace.
	 * Otherwise, it should throw an exception.
	 * 
	 * @param range the range. NOTE: The target is only required to support length-1 execution
	 *            breakpoints.
	 * @param kinds the kind(s) of the breakpoint.
	 * @param condition optionally, a condition for the breakpoint, expressed in the back-end's
	 *            language. NOTE: May be silently ignored by the implementation, if not supported.
	 * @param commands optionally, a command to execute upon hitting the breakpoint, expressed in
	 *            the back-end's language. NOTE: May be silently ignored by the implementation, if
	 *            not supported.
	 */
	void placeBreakpoint(AddressRange range, Set<TraceBreakpointKind> kinds, String condition,
			String commands);

	/**
	 * Check if the given breakpoint (location) is still valid on target
	 * 
	 * @param breakpoint the breakpoint
	 * @return true if valid
	 */
	boolean isBreakpointValid(TraceBreakpoint breakpoint);

	/**
	 * @see #deleteBreakpoint(TraceBreakpoint)
	 */
	CompletableFuture<Void> deleteBreakpointAsync(TraceBreakpoint breakpoint);

	/**
	 * Delete the given breakpoint from the target
	 * 
	 * <p>
	 * If successful, this method must cause the breakpoint removal to be recorded in the trace.
	 * Otherwise, it should throw an exception.
	 * 
	 * @param breakpoint the breakpoint to delete
	 */
	void deleteBreakpoint(TraceBreakpoint breakpoint);

	/**
	 * @see #toggleBreakpoint(TraceBreakpoint, boolean)
	 */
	CompletableFuture<Void> toggleBreakpointAsync(TraceBreakpoint breakpoint, boolean enabled);

	/**
	 * Toggle the given breakpoint on the target
	 * 
	 * <p>
	 * If successful, this method must cause the breakpoint toggle to be recorded in the trace. If
	 * the state is already as desired, this method may have no effect. If unsuccessful, this method
	 * should throw an exception.
	 * 
	 * @param breakpoint the breakpoint to toggle
	 * @param enabled true to enable, false to disable
	 */
	void toggleBreakpoint(TraceBreakpoint breakpoint, boolean enabled);

	/**
	 * @see #forceTerminate()
	 */
	CompletableFuture<Void> forceTerminateAsync();

	/**
	 * Forcefully terminate the target
	 * 
	 * <p>
	 * This will first attempt to kill the target gracefully. In addition, and whether or not the
	 * target is successfully terminated, the target will be dissociated from its trace, and the
	 * target will be invalidated. To attempt only a graceful termination, check
	 * {@link #collectActions(ActionName, ActionContext)} with {@link ActionName#KILL}.
	 */
	void forceTerminate();

	/**
	 * @see #disconnect()
	 */
	CompletableFuture<Void> disconnectAsync();

	/**
	 * Terminate the target and its connection
	 * 
	 * <p>
	 * <b>WARNING:</b> This terminates the connection, even if there are other live targets still
	 * using it. One example where this might happen is if the target process launches a child, and
	 * the debugger is configured to remain attached to both. Whether this is expected or acceptable
	 * behavior has not been decided.
	 * 
	 * <p>
	 * <b>NOTE:</b> This method cannot be invoked on the Swing thread, because it may block on I/O.
	 * 
	 * @see #disconnectAsync()
	 */
	void disconnect();
}
