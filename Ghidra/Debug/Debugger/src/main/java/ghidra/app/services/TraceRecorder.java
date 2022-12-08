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
package ghidra.app.services;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.task.TaskMonitor;

/**
 * A recorder from target object, usually a process, to a destination trace
 * 
 * <p>
 * The recorder is the glue from a portion of a debugger's model into a Ghidra trace. As such, this
 * object maintains a mapping between corresponding objects of interest in the model tree to the
 * trace, and that mapping can be queried. In most cases, UI components which deal with tracing need
 * only read the trace in order to populate their display. Several methods are provided for
 * retrieving corresponding objects from the target or trace given that object in the other. These
 * methods may return null for a variety of reasons:
 * 
 * <ol>
 * <li>The particular type may not be supported or of interest to the recorder.</li>
 * <li>The recorder may not have actually recorded the object yet, despite receiving notice.
 * Recording is asynchronous, and it may also be waiting for additional dependencies or attributes
 * before it can create the corresponding trace object.</li>
 * <li>The target object may not longer exist for a given trace object.</li>
 * </ol>
 * 
 * <p>
 * The recorder copies information in one direction; thus, if a trace UI component needs to affect
 * the target, it must do so via the debugger's model. Such components should use the
 * {@code getTarget*} methods in order to find the target object for a given trace object. The
 * effects of calls on recorded target objects are recorded into the trace automatically. Thus, it
 * is not necessary for trace UI components to react to the successful completion of such calls, so
 * long as they're listening for changes to the trace. However, they MUST react to the exceptional
 * completion of such calls, most likely displaying an error dialog.
 */
public interface TraceRecorder {

	/**
	 * Convert breakpoint kind from the target enum to the trace enum
	 * 
	 * @param kind the target kind
	 * @return the trace kind
	 */
	static TraceBreakpointKind targetToTraceBreakpointKind(TargetBreakpointKind kind) {
		switch (kind) {
			case READ:
				return TraceBreakpointKind.READ;
			case WRITE:
				return TraceBreakpointKind.WRITE;
			case HW_EXECUTE:
				return TraceBreakpointKind.HW_EXECUTE;
			case SW_EXECUTE:
				return TraceBreakpointKind.SW_EXECUTE;
			default:
				throw new AssertionError();
		}
	}

	/**
	 * Convert a collection of breakpoint kinds from the target enum to the trace enum
	 * 
	 * @param kinds the target kinds
	 * @return the trace kinds
	 */
	static Set<TraceBreakpointKind> targetToTraceBreakpointKinds(
			Collection<TargetBreakpointKind> kinds) {
		return kinds.stream()
				.map(TraceRecorder::targetToTraceBreakpointKind)
				.collect(Collectors.toSet());
	}

	/**
	 * Convert breakpoint kind from the trace enum to the target enum
	 * 
	 * @param kind
	 * @return
	 */
	static TargetBreakpointKind traceToTargetBreakpointKind(TraceBreakpointKind kind) {
		switch (kind) {
			case READ:
				return TargetBreakpointKind.READ;
			case WRITE:
				return TargetBreakpointKind.WRITE;
			case HW_EXECUTE:
				return TargetBreakpointKind.HW_EXECUTE;
			case SW_EXECUTE:
				return TargetBreakpointKind.SW_EXECUTE;
			default:
				throw new AssertionError();
		}
	}

	/**
	 * Convert a collection of breakpoint kinds from the trace enum to the target enum
	 * 
	 * @param kinds the trace kinds
	 * @return the target kinds
	 */
	static Set<TargetBreakpointKind> traceToTargetBreakpointKinds(
			Collection<TraceBreakpointKind> kinds) {
		return kinds.stream()
				.map(TraceRecorder::traceToTargetBreakpointKind)
				.collect(Collectors.toSet());
	}

	/**
	 * Initialize this recorder, if not already initialized.
	 * 
	 * The model service starts the initialization. This method can be used to react to the
	 * completion of that initialization.
	 * 
	 * @return the future which completes when initialization is complete
	 */
	CompletableFuture<Void> init();

	/**
	 * Get the "root" of the sub-tree being recorded.
	 * 
	 * @return the target object, usually a process
	 */
	TargetObject getTarget();

	/**
	 * Get the destination trace for this recording
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the key for the latest, current snapshot generated by this recorder
	 * 
	 * @return the snap
	 */
	long getSnap();

	/**
	 * Force the recorder to take a snapshot
	 * 
	 * Note that using the {@link TraceTimeManager} of the recorder's destination trace to take a
	 * new snapshot will not advance the recorder's internal snapshot counter. Use this method
	 * instead if you want to create a snapshot manually.
	 * 
	 * @return the new snapshot
	 */
	TraceSnapshot forceSnapshot();

	/**
	 * Check if this recorder is actively recording
	 * 
	 * @return true if recording, false if stopped
	 */
	boolean isRecording();

	/**
	 * Check if recording is active and the given view is at the present
	 * 
	 * <p>
	 * To be at the present means the view's trace and snap matches the recorder's trace and snap.
	 * The recorder must also be actively recording. Otherwise, this returns {@code false}.
	 * 
	 * @return true if the given view is at the present
	 */
	void stopRecording();

	/**
	 * Add a listener to observe recorder events
	 * 
	 * @param listener the listener
	 */
	void addListener(TraceRecorderListener listener);

	/**
	 * Remove a listener
	 * 
	 * @param listener the listener
	 */
	void removeListener(TraceRecorderListener listener);

	/**
	 * Get the target object corresponding to the given trace object
	 * 
	 * @param obj the trace object
	 * @return the target object, or null
	 */
	TargetObject getTargetObject(TraceObject obj);

	/**
	 * Get the trace object corresponding to the given target object
	 * 
	 * @param obj the target object
	 * @return the trace object, or null
	 */
	TraceObject getTraceObject(TargetObject obj);

	/**
	 * Get the target breakpoint location corresponding to the given trace breakpoint
	 * 
	 * @param obj the trace breakpoint
	 * @return the target breakpoint location, or null
	 */
	TargetBreakpointLocation getTargetBreakpoint(TraceBreakpoint bpt);

	/**
	 * Get the trace breakpoint corresponding to the given target breakpoint location
	 * 
	 * @param obj the target breakpoint location
	 * @return the trace breakpoint, or null
	 */
	TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation bpt);

	/**
	 * Get the target memory region corresponding to the given trace memory region
	 * 
	 * @param obj the trace memory region
	 * @return the target memory region, or null
	 */
	TargetMemoryRegion getTargetMemoryRegion(TraceMemoryRegion region);

	/**
	 * Get the trace memory region corresponding to the given target memory region
	 * 
	 * @param obj the target memory region
	 * @return the trace memory region, or null
	 */
	TraceMemoryRegion getTraceMemoryRegion(TargetMemoryRegion region);

	/**
	 * Get the target module corresponding to the given trace module
	 * 
	 * @param obj the trace module
	 * @return the target module, or null
	 */
	TargetModule getTargetModule(TraceModule module);

	/**
	 * Get the trace module corresponding to the given target module
	 * 
	 * @param obj the target module
	 * @return the trace module, or null
	 */
	TraceModule getTraceModule(TargetModule module);

	/**
	 * Get the target section corresponding to the given trace section
	 * 
	 * @param obj the trace section
	 * @return the target section, or null
	 */
	TargetSection getTargetSection(TraceSection section);

	/**
	 * Get the trace section corresponding to the given target section
	 * 
	 * @param obj the target section
	 * @return the trace section, or null
	 */
	TraceSection getTraceSection(TargetSection section);

	/**
	 * Get the target thread corresponding to the given trace thread
	 * 
	 * @param obj the trace thread
	 * @return the target thread, or null
	 */
	TargetThread getTargetThread(TraceThread thread);

	/**
	 * Get the execution state of the given target thread
	 * 
	 * @param thread the target thread
	 * @return the execution state, or null
	 */
	TargetExecutionState getTargetThreadState(TargetThread thread);

	/**
	 * Get the execution state of the given trace thread
	 * 
	 * @param thread the trace thread
	 * @return the execution state, or null
	 */
	TargetExecutionState getTargetThreadState(TraceThread thread);

	/**
	 * Get the target register bank for the given trace thread and frame level
	 * 
	 * <p>
	 * If the model doesn't provide a bank for every frame, then this should only return non-null
	 * for frame level 0, in which case it should return the bank for the given thread.
	 * 
	 * @param thread the thread
	 * @param frameLevel the frame level
	 * @return the bank, or null
	 */
	TargetRegisterBank getTargetRegisterBank(TraceThread thread, int frameLevel);

	/**
	 * Get the trace thread corresponding to the given target thread
	 * 
	 * @param obj the target thread
	 * @return the trace thread, or null
	 */
	TraceThread getTraceThread(TargetThread thread);

	/**
	 * Find the trace thread containing the given successor target object
	 * 
	 * @param successor the target object
	 * @return the trace thread containing the object, or null
	 */
	TraceThread getTraceThreadForSuccessor(TargetObject successor);

	/**
	 * Get the trace stack frame for the given target stack frame
	 * 
	 * @param frame the target stack frame
	 * @return the trace stack frame, or null
	 */
	TraceStackFrame getTraceStackFrame(TargetStackFrame frame);

	/**
	 * Get the trace stack frame containing the given successor target object
	 * 
	 * @param successor the target object
	 * @return the trace stack frame containing the object, or null
	 */
	TraceStackFrame getTraceStackFrameForSuccessor(TargetObject successor);

	/**
	 * Get the target stack frame for the given trace thread and frame level
	 * 
	 * @param thread the thread
	 * @param frameLevel the frame level
	 * @return the stack frame, or null
	 */
	TargetStackFrame getTargetStackFrame(TraceThread thread, int frameLevel);

	/**
	 * Get all the target's threads that are currently alive
	 * 
	 * @return the set of live target threads
	 */
	Set<TargetThread> getLiveTargetThreads();

	/**
	 * Get the register mapper for the given trace thread
	 * 
	 * @param thread the trace thread
	 * @return the mapper, or null
	 */
	DebuggerRegisterMapper getRegisterMapper(TraceThread thread);

	/**
	 * Get the memory mapper for the target
	 * 
	 * @return the mapper, or null
	 */
	DebuggerMemoryMapper getMemoryMapper();

	/**
	 * Check if the given register bank is accessible
	 * 
	 * @param bank the target register bank
	 * @return true if accessible
	 * @deprecated the accessibility concept was never really implemented nor offered anything of
	 *             value. It has no replacement. Instead a model should reject requests its not
	 *             prepared to handle, or queue them up to be processed when it can. If the latter,
	 *             then ideally it should only allow one instance of a given request to be queued.
	 */
	@Deprecated
	boolean isRegisterBankAccessible(TargetRegisterBank bank);

	/**
	 * Check if the register bank for the given trace thread and frame level is accessible
	 * 
	 * @param thread the trace thread
	 * @param frameLevel the frame level
	 * @see #getTargetStackFrame(TraceThread, int)
	 * @see #isRegisterBankAccessible(TargetRegisterBank)
	 * @return true if accessible
	 * @deprecated for the same reasons as {@link #isRegisterBankAccessible(TargetRegisterBank)}
	 */
	@Deprecated
	boolean isRegisterBankAccessible(TraceThread thread, int frameLevel);

	/**
	 * Get the set of accessible target memory, as viewed in the trace
	 * 
	 * @return the computed set
	 */
	AddressSetView getAccessibleMemory();

	/**
	 * Capture a target thread's registers.
	 * 
	 * <p>
	 * Ordinarily, debugger models should gratuitously notify of register value changes.
	 * Nevertheless, this method can force the retrieval of a given set of registers from the
	 * target.
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread the trace thread associated with the desired target thread
	 * @param frameLevel the number of stack frames to "unwind", likely 0
	 * @param registers the <em>base</em> registers, as viewed by the trace
	 * @return a future which completes when the commands succeed
	 * @throws IllegalArgumentException if no {@link TargetRegisterBank} is known for the given
	 *             thread
	 */
	CompletableFuture<Void> captureThreadRegisters(TracePlatform platform,
			TraceThread thread, int frameLevel, Set<Register> registers);

	/**
	 * Write a target thread's registers.
	 * 
	 * <p>
	 * Note that the model and recorder should cause values successfully written on the target to be
	 * updated in the trace. The caller should not update the trace out of band.
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread the trace thread associated with the desired target thread
	 * @param frameLevel the number of stack frames to "unwind", likely 0
	 * @param values the values to write
	 * @return a future which completes when the registers have been captured.
	 * @throws IllegalArgumentException if no {@link TargetRegisterBank} is known for the given
	 *             thread
	 */
	CompletableFuture<Void> writeThreadRegisters(TracePlatform platform, TraceThread thread,
			int frameLevel, Map<Register, RegisterValue> values);

	/**
	 * Read (and capture) a range of target memory
	 * 
	 * @param start the address to start at, as viewed in the trace
	 * @param length the number of bytes to read
	 * @return a future which completes with the read bytes
	 */
	CompletableFuture<byte[]> readMemory(Address start, int length);

	/**
	 * Write (and capture) a range of target memory
	 * 
	 * @param start the address to start at, as viewed in the trace
	 * @param data the data to write
	 * @return a future which completes when the entire write is complete
	 */
	CompletableFuture<Void> writeMemory(Address start, byte[] data);

	/**
	 * Read (and capture) several blocks of target memory
	 * 
	 * <p>
	 * The given address set is quantized to the minimal set of blocks covering the requested set.
	 * To capture a precise range, use {@link #readMemory(Address, int)} instead. Though this
	 * function returns immediately, the given monitor will be updated in the background as the task
	 * progresses. Thus, the caller should ensure the monitor is visible until the returned future
	 * completes.
	 * 
	 * <p>
	 * This task is relatively error tolerant. If a block or region cannot be captured -- a common
	 * occurrence -- the error is logged, but the task may still complete "successfully."
	 * 
	 * @param set the addresses to capture, as viewed in the trace
	 * @param monitor a monitor for displaying task steps
	 * @param returnResult true to complete with results, false to complete with null
	 * @return a future which completes when the task finishes
	 */
	CompletableFuture<Void> readMemoryBlocks(AddressSetView set, TaskMonitor monitor);

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
	 * @return a future which completes when the write is complete
	 */
	default CompletableFuture<Void> writeVariable(TracePlatform platform, TraceThread thread,
			int frameLevel, Address address, byte[] data) {
		if (address.isMemoryAddress()) {
			return writeMemory(address, data);
		}
		if (address.isRegisterAddress()) {
			return writeRegister(platform, thread, frameLevel, address, data);
		}
		throw new IllegalArgumentException("Address is not in a recognized space: " + address);
	}

	/**
	 * Write a register (by address) of the given thread
	 * 
	 * @param thread the thread
	 * @param frameLevel the frame, usually 0.
	 * @param address the address of the register
	 * @param data the value to write
	 * @return a future which completes when the write is complete
	 */
	default CompletableFuture<Void> writeRegister(TracePlatform platform, TraceThread thread,
			int frameLevel, Address address, byte[] data) {
		Register register = platform.getLanguage().getRegister(address, data.length);
		if (register == null) {
			throw new IllegalArgumentException(
				"Cannot identify the (single) register to write: " + address);
		}

		RegisterValue rv = new RegisterValue(register,
			Utils.bytesToBigInteger(data, data.length, register.isBigEndian(), false));
		TraceMemorySpace regs =
			getTrace().getMemoryManager().getMemoryRegisterSpace(thread, frameLevel, false);
		Register parent = isRegisterOnTarget(platform, thread, frameLevel, register);
		if (parent == null) {
			throw new IllegalArgumentException("Cannot find register " + register + " on target");
		}
		rv = TraceRegisterUtils.combineWithTraceParentRegisterValue(parent, rv, platform, getSnap(),
			regs, true);
		return writeThreadRegisters(platform, thread, frameLevel, Map.of(rv.getRegister(), rv));
	}

	/**
	 * Check if the given register exists on target (is mappable) for the given thread
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread the thread whose registers to examine
	 * @param frameLevel the frame, usually 0.
	 * @param register the register to check
	 * @return the smallest parent register known for the given thread on target, or null
	 */
	Register isRegisterOnTarget(TracePlatform platform, TraceThread thread, int frameLevel,
			Register register);

	/**
	 * Check if the given trace address exists in target memory
	 * 
	 * @param address the address to check
	 * @return true if the given trace address can be mapped to the target's memory
	 */
	default boolean isMemoryOnTarget(Address address) {
		return getMemoryMapper().traceToTarget(address) != null;
	}

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
	default boolean isVariableOnTarget(TracePlatform platform, TraceThread thread, int frameLevel,
			Address address, int size) {
		if (address.isMemoryAddress()) {
			return isMemoryOnTarget(address);
		}
		Register register = platform.getLanguage().getRegister(address, size);
		if (register == null) {
			throw new IllegalArgumentException("Cannot identify the (single) register: " + address);
		}

		// TODO: Can any debugger modify regs up the stack?
		if (frameLevel != 0) {
			return false;
		}

		return isRegisterOnTarget(platform, thread, frameLevel, register) != null;
	}

	/**
	 * Capture the data types of a target's module.
	 * 
	 * <p>
	 * Though this function returns immediately, the given monitor will be updated in the background
	 * as the task progresses. Thus, the caller should ensure the monitor is visible until the
	 * returned future completes.
	 * 
	 * @param module the module whose types to capture
	 * @param monitor a monitor for displaying task steps
	 * @return a future which completes when the types have been captured.
	 */
	CompletableFuture<Void> captureDataTypes(TraceModule module, TaskMonitor monitor);

	/**
	 * Capture the data types of a target's namespace.
	 * 
	 * <p>
	 * Though this function returns immediately, the given monitor will be updated in the background
	 * as the task progresses. Thus, the caller should ensure the monitor is visible until the
	 * returned future completes.
	 * 
	 * @param namespace the namespace whose types to capture
	 * @param monitor a monitor for displaying task steps
	 * @return a future which completes when the types have been captured.
	 */
	CompletableFuture<Void> captureDataTypes(TargetDataTypeNamespace namespace,
			TaskMonitor monitor);

	/**
	 * Capture the symbols of a target's module.
	 * 
	 * <p>
	 * Though this function returns immediately, the given monitor will be updated in the background
	 * as the task progresses. Thus, the caller should ensure the monitor is visible until the
	 * returned future completes.
	 * 
	 * @param module the module whose symbols to capture
	 * @param monitor a monitor for displaying task steps
	 * @return a future which completes when the symbols have been captured.
	 */
	CompletableFuture<Void> captureSymbols(TraceModule module, TaskMonitor monitor);

	/**
	 * Capture the symbols of a target's namespace.
	 * 
	 * <p>
	 * Though this function returns immediately, the given monitor will be updated in the background
	 * as the task progresses. Thus, the caller should ensure the monitor is visible until the
	 * returned future completes.
	 * 
	 * @param namespace the namespace whose symbols to capture
	 * @param monitor a monitor for displaying task steps
	 * @return a future which completes when the symbols have been captured.
	 */
	CompletableFuture<Void> captureSymbols(TargetSymbolNamespace namespace, TaskMonitor monitor);

	/**
	 * Collect breakpoint containers pertinent to the target or a given thread
	 * 
	 * <p>
	 * This is commonly used to set a breakpoint on the appropriate container(s), since the recorder
	 * is already tracking the container according to established conventions. If preferred,
	 * breakpoints can be set directly on the model. The recorder will keep track accordingly either
	 * way.
	 * 
	 * <p>
	 * If a thread is given, the recorder will include only the breakpoint container(s) pertinent to
	 * the given thread. Otherwise, it'll prefer only the process's breakpoint container. If the
	 * process doesn't have a breakpoint container, it'll include all containers pertinent to any
	 * thread in the process.
	 * 
	 * @param thread an optional thread, or {@code null} for the process
	 * @return the list of collected containers, possibly empty
	 */
	List<TargetBreakpointSpecContainer> collectBreakpointContainers(TargetThread thread);

	/**
	 * Collect effective breakpoint pertinent to the target or a given thread
	 * 
	 * <p>
	 * If a thread is given, the recorder will include only the breakpoints pertinent to the given
	 * thread. Otherwise, it'll include every breakpoint pertinent to the process.
	 * 
	 * @param thread an optional thread, or {@code null} for the process
	 * @return the list of collected breakpoints, possibly empty
	 */
	List<TargetBreakpointLocation> collectBreakpoints(TargetThread thread);

	/**
	 * Get the kinds of breakpoints supported by any of the recorded breakpoint containers.
	 * 
	 * This is the union of all kinds supported among all {@link TargetBreakpointSpecContainer}s
	 * found applicable to the target by this recorder. Chances are, there is only one container.
	 * 
	 * @return the set of supported kinds
	 */
	Set<TraceBreakpointKind> getSupportedBreakpointKinds();

	/**
	 * Check if the target is subject to a {@link TargetEventScope}.
	 * 
	 * @return true if an applicable scope is found, false otherwise.
	 */
	boolean isSupportsFocus();

	/**
	 * Get the last-focused object as observed by this recorder
	 * 
	 * @impNote While focus events are not recorded in the trace, it's most fitting to process these
	 *          events in the recorder. We'd like to track them per container, and we already have
	 *          established a one-to-one map of containers to recorders, and each recorder already
	 *          has the appropriate listener installed on the container sub-tree.
	 * @return the object which last had focus within this container, if applicable
	 */
	TargetObject getFocus();

	/**
	 * Request focus on a successor of the target
	 * 
	 * <p>
	 * The object must also be a successor of the focus scope, which is most cases is an ancestor of
	 * the target anyway. If this operation succeeds, the returned future completes with true.
	 * Otherwise, it logs the exception and completes with false. This is a convenience so that
	 * callers do not need to worry that it returns a future, unless they'd like to check for
	 * success.
	 * 
	 * @param focus the object on which to focus
	 * @return a future which completes with true if the operation was successful, false otherwise.
	 */
	CompletableFuture<Boolean> requestFocus(TargetObject focus);

	/**
	 * Wait for pending transactions finish execution.
	 * 
	 * <p>
	 * The returned future will complete when queued transactions have been executed. There are no
	 * guarantees regarding transactions submitted after this future is returned. Furthermore, it
	 * may still be necessary to wait for the trace to finish invoking its domain object change
	 * listeners.
	 * 
	 * @return the future which completes when pending transactions finish execution.
	 */
	CompletableFuture<Void> flushTransactions();
}
