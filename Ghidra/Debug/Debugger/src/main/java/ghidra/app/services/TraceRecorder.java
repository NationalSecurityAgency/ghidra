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
import ghidra.app.plugin.core.debug.service.model.TraceEventListener;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.lifecycle.Internal;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.stack.TraceStackFrame;
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
 * only read the trace in order to populate their display.
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

	TargetBreakpointLocation getTargetBreakpoint(TraceBreakpoint bpt);

	TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation bpt);

	TargetMemoryRegion getTargetMemoryRegion(TraceMemoryRegion region);

	TraceMemoryRegion getTraceMemoryRegion(TargetMemoryRegion region);

	TargetModule getTargetModule(TraceModule module);

	TraceModule getTraceModule(TargetModule module);

	TargetSection getTargetSection(TraceSection section);

	TraceSection getTraceSection(TargetSection section);

	TargetThread getTargetThread(TraceThread thread);

	TargetExecutionState getTargetThreadState(TargetThread thread);

	TargetExecutionState getTargetThreadState(TraceThread thread);

	TargetRegisterBank getTargetRegisterBank(TraceThread thread, int frameLevel);

	TraceThread getTraceThread(TargetThread thread);

	TraceThread getTraceThreadForSuccessor(TargetObject successor);

	TraceStackFrame getTraceStackFrame(TargetStackFrame frame);

	TraceStackFrame getTraceStackFrameForSuccessor(TargetObject successor);

	TargetStackFrame getTargetStackFrame(TraceThread thread, int frameLevel);

	Set<TargetThread> getLiveTargetThreads();

	DebuggerRegisterMapper getRegisterMapper(TraceThread thread);

	DebuggerMemoryMapper getMemoryMapper();

	boolean isRegisterBankAccessible(TargetRegisterBank bank);

	boolean isRegisterBankAccessible(TraceThread thread, int frameLevel);

	/**
	 * Get the set of accessible process memory, as viewed in the trace
	 * 
	 * @return the computed set
	 */
	AddressSetView getAccessibleProcessMemory();

	/**
	 * Capture a target thread's registers.
	 * 
	 * <p>
	 * Ordinarily, debugger models should gratuitously notify of register value changes.
	 * Nevertheless, this method can force the retrieval of a given set of registers from the
	 * target.
	 * 
	 * @param thread the trace thread associated with the desired target thread
	 * @param frameLevel the number of stack frames to "unwind", likely 0
	 * @param registers the <em>base</em> registers, as viewed by the trace
	 * @return a future which completes with the captured values
	 * @throws IllegalArgumentException if no {@link TargetRegisterBank} is known for the given
	 *             thread
	 */
	CompletableFuture<Map<Register, RegisterValue>> captureThreadRegisters(TraceThread thread,
			int frameLevel, Set<Register> registers);

	/**
	 * Write a target thread's registers.
	 * 
	 * <p>
	 * Note that the model and recorder should cause values successfully written on the target to be
	 * updated in the trace. The caller should not update the trace out of band.
	 * 
	 * @param thread the trace thread associated with the desired target thread
	 * @param frameLevel the number of stack frames to "unwind", likely 0
	 * @param values the values to write
	 * @return a future which completes when the registers have been captured.
	 * @throws IllegalArgumentException if no {@link TargetRegisterBank} is known for the given
	 *             thread
	 */
	CompletableFuture<Void> writeThreadRegisters(TraceThread thread, int frameLevel,
			Map<Register, RegisterValue> values);

	/**
	 * Read (and capture) a range of process memory
	 * 
	 * <p>
	 * This will not quantize the blocks; whereas
	 * {@link #captureProcessMemory(AddressSetView, TaskMonitor)} will.
	 * 
	 * @param start the address to start at, as viewed in the trace
	 * @param length the number of bytes to read
	 * @return a future which completes with the read bytes
	 */
	CompletableFuture<byte[]> readProcessMemory(Address start, int length);

	/**
	 * Write (and capture) a range of process memory
	 * 
	 * @param start the address to start at, as viewed in the trace
	 * @param data the data to write
	 * @return a future which completes when the entire write is complete
	 */
	CompletableFuture<Void> writeProcessMemory(Address start, byte[] data);

	/**
	 * Capture a portion of the target's memory.
	 * 
	 * <p>
	 * Though this function returns immediately, the given monitor will be updated in the background
	 * as the task progresses. Thus, the caller should ensure the monitor is visible until the
	 * returned future completes.
	 * 
	 * <p>
	 * This task is relatively error tolerant. If a block or region cannot be captured -- a common
	 * occurrence -- the error is logged, but the future may still complete successfully. For large
	 * captures, it is recommended to set {@code toMap} to false. The recorder will place the bytes
	 * into the trace where they can be retrieved later. For small captures, and where bypassing the
	 * database may offer some advantage, set {@code toMap} to true, and the captured bytes will be
	 * returned in an interval map. Connected intervals may or may not be joined.
	 * 
	 * @param selection the addresses to capture, as viewed in the trace
	 * @param monitor a monitor for displaying task steps
	 * @param toMap true to return results in a map, false to complete with null
	 * @return a future which completes with the capture results
	 */
	CompletableFuture<NavigableMap<Address, byte[]>> captureProcessMemory(AddressSetView selection,
			TaskMonitor monitor, boolean toMap);

	/**
	 * Write a variable (memory or register) of the given thread or the process
	 * 
	 * <p>
	 * This is a convenience for writing target memory or registers, based on address. If the given
	 * address represents a register, this will attempt to map it to a register and write it in the
	 * given thread and frame. If the address is in memory, it will simply delegate to
	 * {@link #writeProcessMemory(Address, byte[])}.
	 * 
	 * @param thread the thread. Ignored (may be null) if address is in memory
	 * @param frameLevel the frame, usually 0. Ignored if address is in memory
	 * @param address the starting address
	 * @param data the value to write
	 * @return a future which completes when the write is complete
	 */
	default CompletableFuture<Void> writeVariable(TraceThread thread, int frameLevel,
			Address address, byte[] data) {
		if (address.isMemoryAddress()) {
			return writeProcessMemory(address, data);
		}
		if (address.isRegisterAddress()) {
			Language lang = getTrace().getBaseLanguage();
			Register register = lang.getRegister(address, data.length);
			if (register == null) {
				throw new IllegalArgumentException(
					"Cannot identify the (single) register to write: " + address);
			}

			RegisterValue rv = new RegisterValue(register,
				Utils.bytesToBigInteger(data, data.length, lang.isBigEndian(), false));
			TraceMemoryRegisterSpace regs =
				getTrace().getMemoryManager().getMemoryRegisterSpace(thread, frameLevel, false);
			rv = TraceRegisterUtils.combineWithTraceBaseRegisterValue(rv, getSnap(), regs, true);
			return writeThreadRegisters(thread, frameLevel, Map.of(rv.getRegister(), rv));
		}
		throw new IllegalArgumentException("Address is not in a recognized space: " + address);
	}

	/**
	 * Check if the given register exists on target (is mappable) for the given thread
	 * 
	 * @param thread the thread whose registers to examine
	 * @param register the register to check
	 * @return true if the given register is known for the given thread on target
	 */
	default boolean isRegisterOnTarget(TraceThread thread, Register register) {
		Collection<Register> onTarget = getRegisterMapper(thread).getRegistersOnTarget();
		return onTarget.contains(register) || onTarget.contains(register.getBaseRegister());
	}

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
	 * @param thread if a register, the thread whose registers to examine
	 * @param address the address of the variable
	 * @param size the size of the variable. Ignored for memory
	 * @return true if the variable can be mapped to the target
	 */
	default boolean isVariableOnTarget(TraceThread thread, Address address, int size) {
		if (address.isMemoryAddress()) {
			return isMemoryOnTarget(address);
		}
		Register register = getTrace().getBaseLanguage().getRegister(address, size);
		if (register == null) {
			throw new IllegalArgumentException("Cannot identify the (single) register: " + address);
		}

		return isRegisterOnTarget(thread, register);
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
	 * Get the internal listener on the model used by the recorder
	 * 
	 * <p>
	 * This allows external "hints" to be given to the recorder by manually injecting objects into
	 * its listener.
	 * 
	 * <p>
	 * TODO: This is a bit of a stop-gap until we have a better way of drawing the recorder's
	 * attention to certain object, or otherwise controlling what it records.
	 * 
	 * @return the listener
	 */
	@Internal
	TraceEventListener getListenerForRecord();

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
