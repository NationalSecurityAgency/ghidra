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
import java.util.function.Supplier;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
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
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface Target {
	long TIMEOUT_MILLIS = 10000;

	record ActionEntry(String display, ActionName name, String details, boolean requiresPrompt,
			BooleanSupplier enabled, Supplier<CompletableFuture<?>> action) {

		public boolean isEnabled() {
			return enabled.getAsBoolean();
		}

		public CompletableFuture<?> invokeAsync(boolean prompt) {
			return action.get().orTimeout(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		}

		public CompletableFuture<?> invokeAsyncLogged(boolean prompt, PluginTool tool) {
			return invokeAsync(prompt).exceptionally(ex -> {
				if (tool != null) {
					tool.setStatusInfo(display + " failed: " + ex, true);
				}
				Msg.error(this, display + " failed: " + ex, ex);
				return ExceptionUtils.rethrow(ex);
			});
		}

		public void run(boolean prompt) {
			get(prompt);
		}

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
	}

	boolean isValid();

	Trace getTrace();

	long getSnap();

	Map<String, ActionEntry> collectActions(ActionName name, ActionContext context);

	TraceThread getThreadForSuccessor(TraceObjectKeyPath path);

	TargetExecutionState getThreadExecutionState(TraceThread thread);

	TraceStackFrame getStackFrameForSuccessor(TraceObjectKeyPath path);

	boolean isSupportsFocus();

	TraceObjectKeyPath getFocus();

	CompletableFuture<Void> activateAsync(DebuggerCoordinates prev, DebuggerCoordinates coords);

	void activate(DebuggerCoordinates prev, DebuggerCoordinates coords);

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
	CompletableFuture<Void> invalidateMemoryCachesAsync();

	/**
	 * See {@link #invalidateMemoryCachesAsync()}
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
	 * containing any portion of the requested set.
	 * 
	 * <p>
	 * This task is relatively error tolerant. If a range cannot be captured -- a common occurrence
	 * -- the error is logged without throwing an exception.
	 * 
	 * @param set the addresses to capture
	 * @param monitor a monitor for displaying task steps
	 * @throws CancelledException if the operation is cancelled
	 */
	void readMemory(AddressSetView set, TaskMonitor monitor) throws CancelledException;

	CompletableFuture<Void> writeMemoryAsync(Address address, byte[] data);

	void writeMemory(Address address, byte[] data);

	CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, Set<Register> registers);

	void readRegisters(TracePlatform platform, TraceThread thread, int frame,
			Set<Register> registers);

	CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, AddressSetView guestSet);

	void readRegisters(TracePlatform platform, TraceThread thread, int frame,
			AddressSetView guestSet);

	CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, RegisterValue value);

	void writeRegister(TracePlatform platform, TraceThread thread, int frame, RegisterValue value);

	CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, Address address, byte[] data);

	void writeRegister(TracePlatform platform, TraceThread thread, int frame, Address address,
			byte[] data);

	/**
	 * Check if a given variable (register or memory) exists on target
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread if a register, the thread whose registers to examine
	 * @param frameLevel the frame, usually 0.
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

	Set<TraceBreakpointKind> getSupportedBreakpointKinds();

	CompletableFuture<Void> placeBreakpointAsync(AddressRange range,
			Set<TraceBreakpointKind> kinds, String condition, String commands);

	void placeBreakpoint(AddressRange range, Set<TraceBreakpointKind> kinds, String condition,
			String commands);

	/**
	 * Check if the given breakpoint (location) is still valid on target
	 * 
	 * @param breakpoint the breakpoint
	 * @return true if valid
	 */
	boolean isBreakpointValid(TraceBreakpoint breakpoint);

	CompletableFuture<Void> deleteBreakpointAsync(TraceBreakpoint breakpoint);

	void deleteBreakpoint(TraceBreakpoint breakpoint);

	CompletableFuture<Void> toggleBreakpointAsync(TraceBreakpoint breakpoint, boolean enabled);

	void toggleBreakpoint(TraceBreakpoint breakpoint, boolean enabled);

	/**
	 * Terminate the target and its connection
	 * 
	 * <p>
	 * <b>WARNING:</b> This terminates the connection, even if there are other live targets still
	 * using it. One example where this might happen is if the target process launches a child, and
	 * the debugger is configured to remain attached to both. Whether this is expected or acceptable
	 * behavior has not been decided.
	 * 
	 * @see #disconnect()
	 */
	CompletableFuture<Void> disconnectAsync();

	/**
	 * Terminate the target and its connection
	 * 
	 * <p>
	 * <b>NOTE:</b> This method cannot be invoked on the Swing thread, because it may block on I/O.
	 * 
	 * @see #disconnectAsync()
	 */
	void disconnect();
}
