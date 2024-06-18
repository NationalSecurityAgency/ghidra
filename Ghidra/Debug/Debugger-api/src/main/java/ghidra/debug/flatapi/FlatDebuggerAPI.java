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
package ghidra.debug.flatapi;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import docking.ActionContext;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.debug.api.model.DebuggerSingleObjectPathActionContext;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.*;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.MathUtilities;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This interface is a flattened version of the Debugger and Trace APIs.
 * 
 * <p>
 * To use this "mix-in" interface, extend {@link GhidraScript} as you normally would for your
 * script, but also add this interface to the {@code implements} clause of your script, e.g.,
 * {@code class MyDebuggerScript extends GhidraScript implements FlatDebuggerAPI}.
 */
public interface FlatDebuggerAPI {

	/**
	 * The method used to wait on futures.
	 * 
	 * <p>
	 * By default, this waits at most 1 minute.
	 * 
	 * @param <T> the type of the result
	 * @param cf the future
	 * @return the result
	 * @throws InterruptedException if execution is interrupted
	 * @throws ExecutionException if an error occurs
	 * @throws TimeoutException if the future does not complete in time
	 */
	default <T> T waitOn(CompletableFuture<T> cf)
			throws InterruptedException, ExecutionException, TimeoutException {
		return cf.get(1, TimeUnit.MINUTES);
	}

	/**
	 * Get the script state
	 * 
	 * <p>
	 * This is required to get various debugger services. It should be implemented by virtue of
	 * extending {@link GhidraScript}.
	 * 
	 * @return the state
	 */
	GhidraState getState();

	/**
	 * Require a service from the tool
	 * 
	 * <p>
	 * If the service is missing, an exception is thrown directing the user to run the script from
	 * the Debugger tool.
	 * 
	 * @param <T> the type of the service
	 * @param cls the class of the service
	 * @return the service
	 * @throws IllegalStateException if the service is missing
	 */
	default <T> T requireService(Class<T> cls) {
		T service = getState().getTool().getService(cls);
		if (service == null) {
			throw new IllegalStateException("Tool does not have service " + cls +
				"! This script should be run from the Debugger tool");
		}
		return service;
	}

	/**
	 * Get the trace manager service
	 * 
	 * @return the service
	 */
	default DebuggerTraceManagerService getTraceManager() {
		return requireService(DebuggerTraceManagerService.class);
	}

	/**
	 * Open the given trace in the UI
	 * 
	 * @param trace the trace
	 */
	default void openTrace(Trace trace) {
		getTraceManager().openTrace(trace);
	}

	/**
	 * Close the given trace in the UI
	 * 
	 * @param trace the trace
	 */
	default void closeTrace(Trace trace) {
		getTraceManager().closeTrace(trace);
	}

	/**
	 * Get the current "coordinates", i.e., trace, thread, frame, snap, etc., usually for the active
	 * target.
	 * 
	 * @return the coordinates
	 */
	default DebuggerCoordinates getCurrentDebuggerCoordinates() {
		return getTraceManager().getCurrent();
	}

	/**
	 * Get the current trace
	 * 
	 * @see #getCurrentDebuggerCoordinates()
	 * @return the trace, or null
	 */
	default Trace getCurrentTrace() {
		return getTraceManager().getCurrentTrace();
	}

	/**
	 * Get the current trace, throwing an exception if there isn't one
	 * 
	 * @return the trace
	 * @throws IllegalStateException if there is no current trace
	 */
	default Trace requireCurrentTrace() {
		Trace trace = getCurrentTrace();
		if (trace == null) {
			throw new IllegalStateException("There is no current trace");
		}
		return trace;
	}

	/**
	 * Require that the given trace is not null
	 * 
	 * @param trace the trace
	 * @return the trace
	 * @throws IllegalStateException if the trace is null
	 */
	default Trace requireTrace(Trace trace) {
		if (trace == null) {
			throw new IllegalStateException("There is no trace");
		}
		return trace;
	}

	/**
	 * Get the current trace platform
	 * 
	 * @return the trace platform, or null
	 */
	default TracePlatform getCurrentPlatform() {
		return getTraceManager().getCurrentPlatform();
	}

	/**
	 * Get the current trace platform, throwing an exception if there isn't one
	 * 
	 * @return the trace platform
	 * @throws IllegalStateException if there is no current trace platform
	 */
	default TracePlatform requireCurrentPlatform() {
		TracePlatform platform = getCurrentPlatform();
		if (platform == null) {
			// NB: Yes I've left off "platform"
			// It's less confusing, and if there's a trace, there's always a platform
			throw new IllegalStateException("There is no current trace");
		}
		return platform;
	}

	/**
	 * Require that the given platform is not null
	 * 
	 * @param platform the platform
	 * @return the platform
	 * @throws IllegalStateException if the platform is null
	 */
	default TracePlatform requirePlatform(TracePlatform platform) {
		if (platform == null) {
			throw new IllegalStateException("There is no platform");
		}
		return platform;
	}

	/**
	 * Get the current thread
	 * 
	 * <p>
	 * While uncommon, it is possible for there to be a current trace, but no current thread.
	 * 
	 * @see #getCurrentDebuggerCoordinates()
	 * @return the thread
	 */
	default TraceThread getCurrentThread() {
		return getTraceManager().getCurrentThread();
	}

	/**
	 * Get the current thread, throwing an exception if there isn't one
	 * 
	 * @return the thread
	 * @throws IllegalStateException if there is no current thread
	 */
	default TraceThread requireCurrentThread() {
		TraceThread thread = getCurrentThread();
		if (thread == null) {
			throw new IllegalStateException("There is no current thread");
		}
		return thread;
	}

	/**
	 * Require that the given thread is not null
	 * 
	 * @param thread the thread
	 * @return the thread
	 * @throws IllegalStateException if the thread is null
	 */
	default TraceThread requireThread(TraceThread thread) {
		if (thread == null) {
			throw new IllegalStateException("There is no thread");
		}
		return thread;
	}

	/**
	 * Get the current trace program view
	 * 
	 * <p>
	 * The view is an adapter for traces that allows them to be used as a {@link Program}. However,
	 * it only works for a chosen snapshot. Typically, {@link TraceProgramView#getSnap()} for this
	 * view will give the same result as {@link #getCurrentSnap()}. The exception is when the UI is
	 * displaying emulated (scratch) machine state. In that case, {@link #getCurrentSnap()} will
	 * give the "source" snapshot of the emulated state, and {@link TraceProgramView#getSnap()} will
	 * give the "destination" scratch snapshot. See {@link #getCurrentEmulationSchedule()}.
	 * 
	 * @see #getCurrentDebuggerCoordinates()
	 * @return the view
	 */
	default TraceProgramView getCurrentView() {
		return getTraceManager().getCurrentView();
	}

	/**
	 * Get the current trace view, throwing an exception if there isn't one
	 * 
	 * @return the trace view
	 * @throws IllegalStateException if there is no current trace view
	 */
	default TraceProgramView requireCurrentView() {
		TraceProgramView view = getCurrentView();
		if (view == null) {
			throw new IllegalStateException("There is no current trace view");
		}
		return view;
	}

	/**
	 * Get the current frame, 0 being the innermost
	 * 
	 * <p>
	 * If the target doesn't support frames, this will return 0
	 * 
	 * @see #getCurrentDebuggerCoordinates()
	 * @return the frame
	 */
	default int getCurrentFrame() {
		return getTraceManager().getCurrentFrame();
	}

	/**
	 * Get the current snap, i.e., snapshot key
	 * 
	 * <p>
	 * Snaps are the trace's notion of time. Positive keys should be monotonic with respect to time:
	 * a higher value implies a later point in time. Negative keys do not; they are used as scratch
	 * space, usually for displaying emulated machine states. This value defaults to 0, so it is
	 * only meaningful if there is a current trace.
	 * 
	 * @see #getCurrentDebuggerCoordinates()
	 * @return the snap
	 */
	default long getCurrentSnap() {
		return getTraceManager().getCurrentSnap();
	}

	/**
	 * Get the current emulation schedule
	 * 
	 * <p>
	 * This constitutes the current snapshot and an optional schedule of emulation steps. If there
	 * is a schedule, then the view's snap will be the destination scratch snap rather than the
	 * current snap.
	 * 
	 * @return the emulation schedule
	 */
	default TraceSchedule getCurrentEmulationSchedule() {
		return getTraceManager().getCurrent().getTime();
	}

	/**
	 * Make the given trace the active trace
	 * 
	 * <p>
	 * If the trace is not already open in the tool, it will be opened automatically
	 * 
	 * @param trace the trace
	 */
	default void activateTrace(Trace trace) {
		DebuggerTraceManagerService manager = getTraceManager();
		if (trace == null) {
			manager.activateTrace(null);
			return;
		}
		if (!manager.getOpenTraces().contains(trace)) {
			manager.openTrace(trace);
		}
		manager.activateTrace(trace);
	}

	/**
	 * Make the given thread the active thread
	 * 
	 * <p>
	 * if the trace is not already open in the tool, it will be opened automatically
	 * 
	 * @param thread the thread
	 */
	default void activateThread(TraceThread thread) {
		DebuggerTraceManagerService manager = getTraceManager();
		if (thread == null) {
			manager.activateThread(null);
			return;
		}
		Trace trace = thread.getTrace();
		if (!manager.getOpenTraces().contains(trace)) {
			manager.openTrace(trace);
		}
		manager.activateThread(thread);
	}

	/**
	 * Make the given frame the active frame
	 * 
	 * @param frame the frame level, 0 being the innermost
	 */
	default void activateFrame(int frame) {
		getTraceManager().activateFrame(frame);
	}

	/**
	 * Make the given snapshot the active snapshot
	 * 
	 * <p>
	 * Activating negative snapshot keys is not recommended. The trace manager uses negative keys
	 * for emulation scratch space and will activate them indirectly as needed.
	 * 
	 * @param snap the snapshot key
	 */
	default void activateSnap(long snap) {
		getTraceManager().activateSnap(snap);
	}

	/**
	 * Get the dynamic listing service
	 * 
	 * @return the service
	 */
	default DebuggerListingService getDebuggerListing() {
		return requireService(DebuggerListingService.class);
	}

	/**
	 * Get the current trace program view and address
	 * 
	 * <p>
	 * This constitutes a portion of the debugger coordinates plus the current dynamic address. The
	 * program given by {@link ProgramLocation#getProgram()} can be safely cast to
	 * {@link TraceProgramView}, which should give the same result as {@link #getCurrentView()}.
	 * 
	 * @return the location
	 */
	default ProgramLocation getCurrentDebuggerProgramLocation() {
		return getDebuggerListing().getCurrentLocation();
	}

	/**
	 * Get the current dynamic address
	 * 
	 * @return the dynamic address
	 */
	default Address getCurrentDebuggerAddress() {
		ProgramLocation loc = getCurrentDebuggerProgramLocation();
		return loc == null ? null : loc.getAddress();
	}

	/**
	 * Go to the given dynamic location in the dynamic listing
	 * 
	 * <p>
	 * To "go to" a point in time, use {@link #activateSnap(long)} or
	 * {@link #emulate(Trace, TraceSchedule, TaskMonitor)}.
	 * 
	 * @param location the location, e.g., from {@link #dynamicLocation(String)}
	 * @return true if successful, false otherwise
	 */
	default boolean goToDynamic(ProgramLocation location) {
		return getDebuggerListing().goTo(location, true);
	}

	/**
	 * Go to the given dynamic address in the dynamic listing
	 * 
	 * @param address the destination address
	 * @return true if successful, false otherwise
	 * @see #goToDynamic(ProgramLocation)
	 */
	default boolean goToDynamic(Address address) {
		return goToDynamic(dynamicLocation(address));
	}

	/**
	 * Go to the given dynamic address in the dynamic listing
	 * 
	 * @param addrString the destination address, as a string
	 * @return true if successful, false otherwise
	 * @see #goToDynamic(ProgramLocation)
	 */
	default boolean goToDynamic(String addrString) {
		return goToDynamic(dynamicLocation(addrString));
	}

	/**
	 * Get the static mapping service
	 * 
	 * @return the service
	 */
	default DebuggerStaticMappingService getMappingService() {
		return requireService(DebuggerStaticMappingService.class);
	}

	/**
	 * Get the current program
	 * 
	 * <p>
	 * This is implemented by virtue of extending {@link FlatProgramAPI}, which is inherited via
	 * {@link GhidraScript}.
	 * 
	 * @return the current program
	 */
	default Program getCurrentProgram() {
		return getState().getCurrentProgram();
	}

	/**
	 * Get the current program, throwing an exception if there isn't one.
	 * 
	 * @return the current program
	 * @throws IllegalStateException if there is no current program
	 */
	default Program requireCurrentProgram() {
		Program program = getCurrentProgram();
		if (program == null) {
			throw new IllegalStateException("There is no current program");
		}
		return program;
	}

	/**
	 * Translate the given static location to the corresponding dynamic location
	 * 
	 * <p>
	 * This uses the trace's static mappings (see {@link Trace#getStaticMappingManager()} and
	 * {@link DebuggerStaticMappingService}) to translate a static location to the corresponding
	 * dynamic location in the current trace. If there is no current trace or the location cannot be
	 * translated to the current trace, the result is null. This accommodates link-load-time
	 * relocation, particularly from address-space layout randomization (ASLR).
	 * 
	 * @param location the static location, e.g., from {@link #staticLocation(String)}
	 * @return the dynamic location, or null if not translated
	 */
	default ProgramLocation translateStaticToDynamic(ProgramLocation location) {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		Trace trace = requireCurrentTrace();
		TraceLocation tloc =
			getMappingService().getOpenMappedLocation(trace, location, current.getSnap());
		return tloc == null ? null : new ProgramLocation(current.getView(), tloc.getAddress());
	}

	/**
	 * Translate the given static address to the corresponding dynamic address
	 * 
	 * <p>
	 * This does the same as {@link #translateStaticToDynamic(ProgramLocation)}, but assumes the
	 * address is for the current program. The returned address is for the current trace view.
	 * 
	 * @param address the static address
	 * @return the dynamic address, or null if not translated
	 */
	default Address translateStaticToDynamic(Address address) {
		Program program = requireCurrentProgram();
		ProgramLocation dloc = translateStaticToDynamic(new ProgramLocation(program, address));
		return dloc == null ? null : dloc.getByteAddress();
	}

	/**
	 * Translate the given dynamic location to the corresponding static location
	 * 
	 * <p>
	 * This does the opposite of {@link #translateStaticToDynamic(ProgramLocation)}. The resulting
	 * static location could be for any open program, not just the current one, since a target may
	 * load several images. For example, a single user-space process typically has several modules:
	 * the executable image and several libraries.
	 * 
	 * @param location the dynamic location, e.g., from {@link #dynamicLocation(String)}
	 * @return the static location, or null if not translated
	 */
	default ProgramLocation translateDynamicToStatic(ProgramLocation location) {
		return getMappingService().getStaticLocationFromDynamic(location);
	}

	/**
	 * Translate the given dynamic address to the corresponding static address
	 * 
	 * <p>
	 * This does the same as {@link #translateDynamicToStatic(ProgramLocation)}, but assumes the
	 * address is for the current trace view. The returned address is for the current program. If
	 * there is not current view or program, or if the address cannot be translated to the current
	 * program, null is returned.
	 * 
	 * @param address the dynamic address
	 * @return the static address
	 */
	default Address translateDynamicToStatic(Address address) {
		Program program = requireCurrentProgram();
		TraceProgramView view = requireCurrentView();
		ProgramLocation sloc = translateDynamicToStatic(new ProgramLocation(view, address));
		return sloc == null ? null : sloc.getProgram() != program ? null : sloc.getByteAddress();
	}

	/**
	 * Get the emulation service
	 * 
	 * @return the service
	 */
	default DebuggerEmulationService getEmulationService() {
		return requireService(DebuggerEmulationService.class);
	}

	/**
	 * Load the given program into a trace suitable for emulation in the UI, starting at the given
	 * address
	 * 
	 * <p>
	 * Note that the program bytes are not actually loaded into the trace. Rather a static mapping
	 * is generated, allowing the emulator to load bytes from the target program lazily. The trace
	 * is automatically loaded into the UI (trace manager).
	 * 
	 * @param program the target program
	 * @param address the initial program counter
	 * @return the resulting trace
	 * @throws IOException if the trace cannot be created
	 */
	default Trace emulateLaunch(Program program, Address address) throws IOException {
		return getEmulationService().launchProgram(program, address);
	}

	/**
	 * Does the same as {@link #emulateLaunch(Program, Address)}, for the current program
	 * 
	 * @param address the initial program counter
	 * @return the resulting trace
	 * @throws IOException if the trace cannot be created
	 */
	default Trace emulateLaunch(Address address) throws IOException {
		return emulateLaunch(requireCurrentProgram(), address);
	}

	/**
	 * Emulate the given trace platform as specified in the given schedule and display the result in
	 * the UI
	 * 
	 * @param platform the trace platform
	 * @param time the schedule of steps
	 * @param monitor a monitor for the emulation
	 * @return true if successful
	 * @throws CancelledException if the user cancelled via the given monitor
	 */
	default boolean emulate(TracePlatform platform, TraceSchedule time, TaskMonitor monitor)
			throws CancelledException {
		// Use the script's thread to perform the actual emulation
		getEmulationService().emulate(platform, time, monitor);
		// This should just display the cached state
		getTraceManager().activateTime(time);
		return true;
	}

	/**
	 * Emulate the given trace as specified in the given schedule and display the result in the UI
	 * 
	 * @param trace the trace
	 * @param time the schedule of steps
	 * @param monitor a monitor for the emulation
	 * @return true if successful
	 * @throws CancelledException if the user cancelled via the given monitor
	 */
	default boolean emulate(Trace trace, TraceSchedule time, TaskMonitor monitor)
			throws CancelledException {
		return emulate(trace.getPlatformManager().getHostPlatform(), time, monitor);
	}

	/**
	 * Emulate the current trace as specified and display the result
	 * 
	 * @param time the schedule of steps
	 * @param monitor the monitor for the emulation
	 * @return true if successful
	 * @throws CancelledException if the user cancelled via the given monitor
	 * @throws IllegalStateException if there is no current trace
	 */
	default boolean emulate(TraceSchedule time, TaskMonitor monitor) throws CancelledException {
		return emulate(requireCurrentPlatform(), time, monitor);
	}

	/**
	 * Step the current trace count instructions via emulation
	 * 
	 * @param count the number of instructions to step, negative to step in reverse
	 * @param monitor a monitor for the emulation
	 * @return true if successful, false otherwise
	 * @throws CancelledException if the user cancelled via the given monitor
	 * @throws IllegalStateException if there is no current trace or thread
	 */
	default boolean stepEmuInstruction(long count, TaskMonitor monitor) throws CancelledException {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		TracePlatform platform = requireCurrentPlatform();
		TraceThread thread = current.getThread();
		TraceSchedule time = current.getTime();
		TraceSchedule stepped = count <= 0
				? time.steppedBackward(platform.getTrace(), -count)
				: time.steppedForward(requireThread(thread), count);
		return emulate(platform, stepped, monitor);
	}

	/**
	 * Step the current trace count p-code operations via emulation
	 * 
	 * @param count the number of operations to step, negative to step in reverse
	 * @param monitor a monitor for the emulation
	 * @return true if successful, false otherwise
	 * @throws CancelledException if the user cancelled via the given monitor
	 */
	default boolean stepEmuPcodeOp(int count, TaskMonitor monitor) throws CancelledException {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		TracePlatform platform = requireCurrentPlatform();
		TraceThread thread = current.getThread();
		TraceSchedule time = current.getTime();
		TraceSchedule stepped = count <= 0
				? time.steppedPcodeBackward(-count)
				: time.steppedPcodeForward(requireThread(thread), count);
		return emulate(platform, stepped, monitor);
	}

	/**
	 * Step the current trace count skipped instructions via emulation
	 * 
	 * <p>
	 * Note there's no such thing as "skipping in reverse." If a negative count is given, this will
	 * behave the same as {@link #stepEmuInstruction(long, TaskMonitor)}.
	 * 
	 * @param count the number of instructions to skip, negative to step in reverse
	 * @param monitor a monitor for the emulation
	 * @return true if successful, false otherwise
	 * @throws CancelledException if the user cancelled via the given monitor
	 */
	default boolean skipEmuInstruction(long count, TaskMonitor monitor) throws CancelledException {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		TracePlatform platform = requireCurrentPlatform();
		TraceThread thread = current.getThread();
		TraceSchedule time = current.getTime();
		TraceSchedule stepped = count <= 0
				? time.steppedBackward(platform.getTrace(), -count)
				: time.skippedForward(requireThread(thread), count);
		return emulate(platform, stepped, monitor);
	}

	/**
	 * Step the current trace count skipped p-code operations via emulation
	 * 
	 * <p>
	 * Note there's no such thing as "skipping in reverse." If a negative count is given, this will
	 * behave the same as {@link #stepEmuPcodeOp(int, TaskMonitor)}.
	 * 
	 * @param count the number of operations to skip, negative to step in reverse
	 * @param monitor a monitor for the emulation
	 * @return true if successful, false otherwise
	 * @throws CancelledException if the user cancelled via the given monitor
	 */
	default boolean skipEmuPcodeOp(int count, TaskMonitor monitor) throws CancelledException {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		TracePlatform platform = requireCurrentPlatform();
		TraceThread thread = current.getThread();
		TraceSchedule time = current.getTime();
		TraceSchedule stepped = count <= 0
				? time.steppedPcodeBackward(-count)
				: time.skippedPcodeForward(requireThread(thread), count);
		return emulate(platform, stepped, monitor);
	}

	/**
	 * Apply the given Sleigh patch to the emulator
	 * 
	 * @param sleigh the Sleigh source, without terminating semicolon
	 * @param monitor a monitor for the emulation
	 * @return true if successful, false otherwise
	 * @throws CancelledException if the user cancelled via the given monitor
	 */
	default boolean patchEmu(String sleigh, TaskMonitor monitor) throws CancelledException {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		TracePlatform platform = requireCurrentPlatform();
		TraceThread thread = current.getThread();
		TraceSchedule time = current.getTime();
		TraceSchedule patched = time.patched(requireThread(thread), platform.getLanguage(), sleigh);
		return emulate(platform, patched, monitor);
	}

	/**
	 * Create an address range, avoiding address overflow by truncating
	 * 
	 * <p>
	 * If the length would cause address overflow, it is adjusted such that the range's maximum
	 * address is the space's maximum address.
	 * 
	 * @param start the minimum address
	 * @param length the desired length
	 * @return the range
	 */
	default AddressRange safeRange(Address start, int length) {
		if (length < 0) {
			throw new IllegalArgumentException("length < 0");
		}
		long maxLength = start.getAddressSpace().getMaxAddress().subtract(start);
		try {
			return new AddressRangeImpl(start, MathUtilities.unsignedMin(length, maxLength));
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * The the target service
	 * 
	 * @return the service
	 */
	default DebuggerTargetService getTargetService() {
		return requireService(DebuggerTargetService.class);
	}

	/**
	 * Copy memory from target to trace, if applicable and not already cached
	 * 
	 * @param trace the trace to update
	 * @param snap the snap the snap, to determine whether target bytes are applicable
	 * @param start the starting address
	 * @param length the number of bytes to make fresh
	 * @param monitor a monitor for progress
	 * @throws CancelledException if the operation was cancelled
	 */
	default void refreshMemoryIfLive(Trace trace, long snap, Address start, int length,
			TaskMonitor monitor) throws CancelledException {
		Target target = getTargetService().getTarget(trace);
		if (target == null || target.getSnap() != snap) {
			return;
		}
		target.readMemory(new AddressSet(safeRange(start, length)), monitor);
	}

	/**
	 * Read memory into the given buffer, refreshing from target if needed
	 * 
	 * @param trace the source trace
	 * @param snap the source snap
	 * @param start the source starting address
	 * @param buffer the destination buffer
	 * @param monitor a monitor for live read progress
	 * @return the number of bytes read
	 * @throws CancelledException if the operation was cancelled
	 */
	default int readMemory(Trace trace, long snap, Address start, byte[] buffer,
			TaskMonitor monitor) throws CancelledException {
		refreshMemoryIfLive(trace, snap, start, buffer.length, monitor);
		return trace.getMemoryManager().getViewBytes(snap, start, ByteBuffer.wrap(buffer));
	}

	/**
	 * Read memory, refreshing from target if needed
	 * 
	 * @param trace the source trace
	 * @param snap the source snap
	 * @param start the source starting address
	 * @param length the desired number of bytes
	 * @param monitor a monitor for live read progress
	 * @return the array of bytes read, can be shorter than desired
	 * @throws CancelledException if the operation was cancelled
	 */
	default byte[] readMemory(Trace trace, long snap, Address start, int length,
			TaskMonitor monitor) throws CancelledException {
		byte[] arr = new byte[length];
		int actual = readMemory(trace, snap, start, arr, monitor);
		if (actual == length) {
			return arr;
		}
		return Arrays.copyOf(arr, actual);
	}

	/**
	 * Read memory from the current trace view into the given buffer, refreshing from target if
	 * needed
	 * 
	 * @param start the starting address
	 * @param buffer the destination buffer
	 * @param monitor a monitor for live read progress
	 * @return the number of bytes read
	 * @throws CancelledException if the operation was cancelled
	 */
	default int readMemory(Address start, byte[] buffer, TaskMonitor monitor)
			throws CancelledException {
		TraceProgramView view = requireCurrentView();
		return readMemory(view.getTrace(), view.getSnap(), start, buffer, monitor);
	}

	/**
	 * Read memory for the current trace view, refreshing from target if needed
	 * 
	 * @param start the starting address
	 * @param length the desired number of bytes
	 * @param monitor a monitor for live read progress
	 * @return the array of bytes read, can be shorter than desired
	 * @throws CancelledException if the operation was cancelled
	 */
	default byte[] readMemory(Address start, int length, TaskMonitor monitor)
			throws CancelledException {
		TraceProgramView view = requireCurrentView();
		return readMemory(view.getTrace(), view.getSnap(), start, length, monitor);
	}

	/**
	 * Search trace memory for a given masked byte sequence
	 * 
	 * <p>
	 * <b>NOTE:</b> This searches the trace only. It will not interrogate the live target. There are
	 * two mechanisms for searching a live target's full memory: 1) Capture the full memory (or the
	 * subset to search) -- using, e.g.,
	 * {@link #refreshMemoryIfLive(Trace, long, Address, int, TaskMonitor)} -- then search the
	 * trace. 2) If possible, invoke the target debugger's search functions -- using, e.g.,
	 * {@link #executeCapture(String)}.
	 * 
	 * <p>
	 * This delegates to
	 * {@link TraceMemoryOperations#findBytes(long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)}.
	 * It culls out ranges that have never been recorded, effectively excluding default {@code 00}s.
	 * This can only search a single snapshot per invocation, but it does include stale bytes, i.e.,
	 * those from a previous snapshot without a more up-to-date record. In particular, a stale
	 * {@code 00} is matched as usual, as is any stale byte. Only those ranges which have
	 * <em>never</em> been recorded are culled. While not required, memory is conventionally read
	 * and recorded in pages, so culling tends to occur at page boundaries.
	 * 
	 * <p>
	 * Be wary of leading or trailing wildcards, i.e., masked-out bytes. The full data array must
	 * fit within the given range after culling. For example, suppose the byte {@code 12} is
	 * recorded at {@code ram:00400000}. The full page is recorded, but the preceding page has never
	 * been recorded. Thus, the byte at {@code ram:003fffff} is a default {@code 00}. Searching for
	 * the pattern {@code ?? 12} in the range {@code ram:00400000:00400fff} will not find the match.
	 * This much is intuitive, because the match starts at {@code ram:003fffff}, which is outside
	 * the specified range. However, this rule also affects trailing wildcards. Furthermore, because
	 * the preceding page was never recorded, even if the specified range were
	 * {@code ram:003ff000:00400fff}, the range would be culled, and the match would still be
	 * excluded. Nothing -- not even a wildcard -- can match a default {@code 00}.
	 * 
	 * @param trace the trace to search
	 * @param snap the snapshot of the trace to search
	 * @param range the range within to search
	 * @param data the bytes to search for
	 * @param mask a mask on the bits to search, or null to match exactly.
	 * @param forward true to start at the min address going forward, false to start at the max
	 *            address going backward
	 * @param monitor a monitor for search progress
	 * @return the minimum address of the matched bytes, or null if not found
	 */
	default Address searchMemory(Trace trace, long snap, AddressRange range, ByteBuffer data,
			ByteBuffer mask, boolean forward, TaskMonitor monitor) {
		return trace.getMemoryManager().findBytes(snap, range, data, mask, forward, monitor);
	}

	/**
	 * @see #searchMemory(Trace, long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)
	 * 
	 * @param trace the trace to search
	 * @param snap the snapshot of the trace to search
	 * @param range the range within to search
	 * @param data the bytes to search for
	 * @param mask a mask on the bits to search, or null to match exactly.
	 * @param forward true to start at the min address going forward, false to start at the max
	 *            address going backward
	 * @param monitor a monitor for search progress
	 * @return the minimum address of the matched bytes, or null if not found
	 */
	default Address searchMemory(Trace trace, long snap, AddressRange range, byte[] data,
			byte[] mask, boolean forward, TaskMonitor monitor) {
		return searchMemory(trace, snap, range, ByteBuffer.wrap(data),
			mask == null ? null : ByteBuffer.wrap(mask), forward, monitor);
	}

	/**
	 * Copy registers from target to trace, if applicable and not already cached
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread the trace thread to update
	 * @param frame the frame level, 0 being the innermost
	 * @param snap the snap, to determine whether target values are applicable
	 * @param registers the registers to make fresh
	 */
	default void refreshRegistersIfLive(TracePlatform platform, TraceThread thread, int frame,
			long snap, Collection<Register> registers) {
		Trace trace = thread.getTrace();

		Target target = getTargetService().getTarget(trace);
		if (target == null || target.getSnap() != snap) {
			return;
		}
		Set<Register> asSet = registers instanceof Set<Register> s ? s : Set.copyOf(registers);
		target.readRegisters(platform, thread, frame, asSet);
	}

	/**
	 * Read several registers from the given context, refreshing from target if needed
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread the trace thread
	 * @param frame the source frame level, 0 being the innermost
	 * @param snap the source snap
	 * @param registers the source registers
	 * @return the list of register values, or null on error
	 */
	default List<RegisterValue> readRegisters(TracePlatform platform, TraceThread thread, int frame,
			long snap, Collection<Register> registers) {
		refreshRegistersIfLive(platform, thread, frame, snap, registers);
		TraceMemorySpace regs =
			thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, frame, false);
		if (regs == null) {
			return registers.stream().map(RegisterValue::new).collect(Collectors.toList());
		}
		return registers.stream().map(r -> regs.getValue(snap, r)).collect(Collectors.toList());
	}

	/**
	 * Read a register
	 * 
	 * @param platform the platform whose language defines the registers
	 * @param thread the trace thread
	 * @param frame the source frame level, 0 being the innermost
	 * @param snap the source snap
	 * @param register the source register
	 * @return the register's value, or null on error
	 * @see #readRegisters(TracePlatform, TraceThread, int, long, Collection)
	 */
	default RegisterValue readRegister(TracePlatform platform, TraceThread thread, int frame,
			long snap, Register register) {
		List<RegisterValue> result = readRegisters(platform, thread, frame, snap, Set.of(register));
		return result == null ? null : result.get(0);
	}

	/**
	 * Read several registers from the current context, refreshing from the target if needed
	 * 
	 * @param registers the source registers
	 * @return the list of register values, or null on error
	 * @see #readRegisters(TracePlatform, TraceThread, int, long, Collection)
	 */
	default List<RegisterValue> readRegisters(Collection<Register> registers) {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		return readRegisters(requireCurrentPlatform(), requireThread(current.getThread()),
			current.getFrame(), current.getSnap(), registers);
	}

	/**
	 * Validate and retrieve the named registers
	 * 
	 * @param language the language defining the registers
	 * @param names the names
	 * @return the registers, in the same order
	 * @throws IllegalArgumentException if any name is invalid
	 */
	default List<Register> validateRegisterNames(Language language, Collection<String> names) {
		List<String> invalid = new ArrayList<>();
		List<Register> result = new ArrayList<>();
		for (String n : names) {
			Register register = language.getRegister(n);
			if (register != null) {
				result.add(register);
			}
			else {
				invalid.add(n);
			}
		}
		if (!invalid.isEmpty()) {
			throw new IllegalArgumentException("One or more invalid register names: " + invalid);
		}
		return result;
	}

	/**
	 * Validate and retrieve the name register
	 * 
	 * @param language the language defining the register
	 * @param name the name
	 * @return the register
	 * @throws IllegalArgumentException if the name is invalid
	 */
	default Register validateRegisterName(Language language, String name) {
		Register register = language.getRegister(name);
		if (register == null) {
			throw new IllegalArgumentException("Invalid register name: " + name);
		}
		return register;
	}

	/**
	 * Read several registers from the current context, refreshing from the target if needed
	 * 
	 * @param names the source register names
	 * @return the list of register values, or null on error
	 * @throws IllegalArgumentException if any name is invalid
	 * @see #readRegisters(TracePlatform, TraceThread, int, long, Collection)
	 */
	default List<RegisterValue> readRegistersNamed(Collection<String> names) {
		return readRegisters(validateRegisterNames(requireCurrentTrace().getBaseLanguage(), names));
	}

	/**
	 * Read a register from the current context, refreshing from the target if needed
	 * 
	 * @param platform the platform whose language defines the register
	 * @param register the register
	 * @return the value, or null on error
	 */
	default RegisterValue readRegister(TracePlatform platform, Register register) {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		if (platform.getTrace() != current.getTrace()) {
			throw new IllegalArgumentException("Given platform is not from the current trace");
		}
		Language language = platform.getLanguage();
		if (!register.equals(language.getRegister(register.getName()))) {
			throw new IllegalArgumentException(
				"Register " + register + " is not in language " + language);
		}
		return readRegister(platform, requireThread(current.getThread()), current.getFrame(),
			current.getSnap(), register);
	}

	/**
	 * Read a register from the current context, refreshing from the target if needed
	 * 
	 * @param register the register
	 * @return the value, or null on error
	 */
	default RegisterValue readRegister(Register register) {
		return readRegister(requireCurrentPlatform(), register);
	}

	/**
	 * Read a register from the current context, refreshing from the target if needed
	 * 
	 * @param name the register name
	 * @return the value, or null on error
	 * @throws IllegalArgumentException if the name is invalid
	 * @see #readRegister(Register)
	 */
	default RegisterValue readRegister(String name) {
		TracePlatform platform = requireCurrentPlatform();
		Register register = validateRegisterName(platform.getLanguage(), name);
		return readRegister(platform, register);
	}

	/**
	 * Evaluate a Sleigh expression in the given context
	 * 
	 * @param coordinates the context
	 * @param expression the Sleigh expression
	 * @return the value
	 */
	default BigInteger evaluate(DebuggerCoordinates coordinates, String expression) {
		return TraceSleighUtils.evaluate(expression, coordinates.getTrace(),
			coordinates.getViewSnap(), coordinates.getThread(), coordinates.getFrame());
	}

	/**
	 * Evaluate a Sleigh expression in the current context
	 * 
	 * @param expression the Sleigh expression
	 * @return the value
	 */
	default BigInteger evaluate(String expression) {
		return evaluate(getCurrentDebuggerCoordinates(), expression);
	}

	/**
	 * Get the program counter for the given context
	 * 
	 * @param coordinates the context
	 * @return the program counter, or null if not known
	 */
	default Address getProgramCounter(DebuggerCoordinates coordinates) {
		TracePlatform platform = requirePlatform(coordinates.getPlatform());
		Language language = platform.getLanguage();
		RegisterValue value = readRegister(platform, requireThread(coordinates.getThread()),
			coordinates.getFrame(), coordinates.getSnap(), language.getProgramCounter());
		if (value == null || !value.hasValue()) {
			return null;
		}
		return language.getDefaultSpace().getAddress(value.getUnsignedValue().longValue());
	}

	/**
	 * Get the program counter for the current context
	 * 
	 * @return the program counter, or null if not known
	 */
	default Address getProgramCounter() {
		return getProgramCounter(getCurrentDebuggerCoordinates());
	}

	/**
	 * Get the stack pointer for the given context
	 * 
	 * @param coordinates the context
	 * @return the stack pointer, or null if not known
	 */
	default Address getStackPointer(DebuggerCoordinates coordinates) {
		TracePlatform platform = requirePlatform(coordinates.getPlatform());
		CompilerSpec cSpec = platform.getCompilerSpec();
		RegisterValue value = readRegister(platform, requireThread(coordinates.getThread()),
			coordinates.getFrame(), coordinates.getSnap(), cSpec.getStackPointer());
		if (!value.hasValue()) {
			return null;
		}
		return cSpec.getStackBaseSpace().getAddress(value.getUnsignedValue().longValue());
	}

	/**
	 * Get the stack pointer for the current context
	 * 
	 * @return the stack pointer, or null if not known
	 */
	default Address getStackPointer() {
		return getStackPointer(getCurrentDebuggerCoordinates());
	}

	/**
	 * Get the control service
	 * 
	 * @return the service
	 */
	default DebuggerControlService getControlService() {
		return requireService(DebuggerControlService.class);
	}

	/**
	 * Set the control mode of the given trace
	 * 
	 * @param trace the trace
	 * @param mode the mode
	 */
	default void setControlMode(Trace trace, ControlMode mode) {
		requireService(DebuggerControlService.class).setCurrentMode(trace, mode);
	}

	/**
	 * Set the control mode of the current trace
	 * 
	 * @param mode the mode
	 */
	default void setControlMode(ControlMode mode) {
		setControlMode(requireCurrentTrace(), mode);
	}

	/**
	 * Create a state editor for the given context, adhering to its current control mode
	 * 
	 * @param coordinates the context
	 * @return the editor
	 */
	default StateEditor createStateEditor(DebuggerCoordinates coordinates) {
		return getControlService().createStateEditor(coordinates);
	}

	/**
	 * Create a state editor suitable for memory edits for the given context
	 * 
	 * @param trace the trace
	 * @param snap the snap
	 * @return the editor
	 */
	default StateEditor createStateEditor(Trace trace, long snap) {
		return getControlService().createStateEditor(getTraceManager()
				.resolveTrace(trace)
				.snap(snap));
	}

	/**
	 * Create a state editor suitable for register or memory edits for the given context
	 * 
	 * @param thread the thread
	 * @param frame the frame
	 * @param snap the snap
	 * @return the editor
	 */
	default StateEditor createStateEditor(TraceThread thread, int frame, long snap) {
		return getControlService().createStateEditor(getTraceManager()
				.resolveThread(thread)
				.snap(snap)
				.frame(frame));
	}

	/**
	 * Create a state editor for the current context, adhering to the current control mode
	 * 
	 * @return the editor
	 */
	default StateEditor createStateEditor() {
		return createStateEditor(getCurrentDebuggerCoordinates());
	}

	/**
	 * Patch memory using the given editor
	 * 
	 * <p>
	 * The success or failure of this method depends on a few factors. First is the user-selected
	 * control mode for the trace. See {@link #setControlMode(ControlMode)}. In read-only mode, this
	 * will always fail. When editing traces, a write almost always succeeds. Exceptions would
	 * probably indicate I/O errors. When editing via emulation, a write should almost always
	 * succeed. Second, when editing the target, the state of the target matters. If the trace has
	 * no target, this will always fail. If the target is not accepting commands, e.g., because the
	 * target or debugger is busy, this may fail or be delayed. If the target doesn't support
	 * editing the given space, this will fail. Some debuggers may also deny modification due to
	 * permissions.
	 * 
	 * @param editor the editor
	 * @param start the starting address
	 * @param data the bytes to write
	 * @return true if successful, false otherwise
	 */
	default boolean writeMemory(StateEditor editor, Address start, byte[] data) {
		if (!editor.isVariableEditable(start, data.length)) {
			return false;
		}
		try {
			waitOn(editor.setVariable(start, data));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Patch memory of the given target, according to its current control mode
	 * 
	 * <p>
	 * If you intend to apply several patches, consider using {@link #createStateEditor(Trace,long)}
	 * and {@link #writeMemory(StateEditor, Address, byte[])}
	 * 
	 * @param trace the trace
	 * @param snap the snapshot
	 * @param start the starting address
	 * @param data the bytes to write
	 * @return true if successful, false otherwise
	 */
	default boolean writeMemory(Trace trace, long snap, Address start, byte[] data) {
		return writeMemory(createStateEditor(trace, snap), start, data);
	}

	/**
	 * Patch memory of the current target, according to the current control mode
	 * 
	 * <p>
	 * If you intend to apply several patches, consider using {@link #createStateEditor()} and
	 * {@link #writeMemory(StateEditor, Address, byte[])}
	 * 
	 * @param start the starting address
	 * @param data the bytes to write
	 * @return true if successful, false otherwise
	 */
	default boolean writeMemory(Address start, byte[] data) {
		return writeMemory(createStateEditor(), start, data);
	}

	/**
	 * Patch a register using the given editor
	 * 
	 * <p>
	 * The success or failure of this methods depends on a few factors. First is the user-selected
	 * control mode for the trace. See {@link #setControlMode(ControlMode)}. In read-only mode, this
	 * will always fail. When editing traces, a write almost always succeeds. Exceptions would
	 * probably indicate I/O errors. When editing via emulation, a write should only fail if the
	 * register is not accessible to Sleigh, e.g., the context register. Second, when editing the
	 * target, the state of the target matters. If the trace has no target, this will always fail.
	 * If the target is not accepting commands, e.g., because the target or debugger is busy, this
	 * may fail or be delayed. If the target doesn't support editing the given register, this will
	 * fail.
	 * 
	 * @param editor the editor
	 * @param rv the register value
	 * @return true if successful, false otherwise
	 */
	default boolean writeRegister(StateEditor editor, RegisterValue rv) {
		if (!editor.isRegisterEditable(rv.getRegister())) {
			return false;
		}
		try {
			waitOn(editor.setRegister(rv));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Patch a register of the given context, according to its current control mode
	 * 
	 * <p>
	 * If you intend to apply several patches, consider using
	 * {@link #createStateEditor(TraceThread,int,long)} and
	 * {@link #writeRegister(StateEditor, RegisterValue)}.
	 * 
	 * @param thread the thread
	 * @param frame the frame
	 * @param snap the snap
	 * @param rv the register value
	 * @return true if successful, false otherwise
	 */
	default boolean writeRegister(TraceThread thread, int frame, long snap, RegisterValue rv) {
		return writeRegister(createStateEditor(thread, frame, snap), rv);
	}

	/**
	 * Patch a register of the given context, according to its current control mode
	 * 
	 * @param thread the thread
	 * @param frame the frame
	 * @param snap the snap
	 * @param name the register name
	 * @param value the value
	 * @return true if successful, false otherwise
	 * @throws IllegalArgumentException if the register name is invalid
	 * @see #writeRegister(TraceThread, int, long, RegisterValue)
	 */
	default boolean writeRegister(TraceThread thread, int frame, long snap, String name,
			BigInteger value) {
		return writeRegister(thread, frame, snap, new RegisterValue(
			validateRegisterName(thread.getTrace().getBaseLanguage(), name), value));
	}

	/**
	 * Patch a register of the current thread, according to the current control mode
	 * 
	 * <p>
	 * If you intend to apply several patches, consider using {@link #createStateEditor()} and
	 * {@link #writeRegister(StateEditor, RegisterValue)}.
	 * 
	 * @param rv the register value
	 * @return true if successful, false otherwise
	 */
	default boolean writeRegister(RegisterValue rv) {
		return writeRegister(createStateEditor(), rv);
	}

	/**
	 * Patch a register of the current thread, according to the current control mode
	 * 
	 * @param name the register name
	 * @param value the value
	 * @return true if successful, false otherwise
	 * @throws IllegalArgumentException if the register name is invalid
	 * @see #writeRegister(RegisterValue)
	 */
	default boolean writeRegister(String name, BigInteger value) {
		return writeRegister(new RegisterValue(
			validateRegisterName(requireCurrentTrace().getBaseLanguage(), name), value));
	}

	default ActionContext createContext(TraceObject object) {
		TraceObjectValue value = object.getCanonicalParents(Lifespan.ALL).findAny().orElseThrow();
		return new DebuggerObjectActionContext(List.of(value), null, null);
	}

	default ActionContext createContext(TraceThread thread) {
		if (thread instanceof TraceObjectThread objThread) {
			return createContext(objThread.getObject());
		}
		return new DebuggerSingleObjectPathActionContext(
			TraceObjectKeyPath.parse(thread.getPath()));
	}

	default ActionContext createContext(Trace trace) {
		DebuggerCoordinates coords = getTraceManager().getCurrentFor(trace);
		if (coords == null) {
			return new DebuggerSingleObjectPathActionContext(TraceObjectKeyPath.of());
		}
		if (coords.getObject() != null) {
			return createContext(coords.getObject());
		}
		if (coords.getPath() != null) {
			return new DebuggerSingleObjectPathActionContext(coords.getPath());
		}
		return new DebuggerSingleObjectPathActionContext(TraceObjectKeyPath.of());
	}

	default ActionEntry findAction(Target target, ActionName action, ActionContext context) {
		return target.collectActions(action, context)
				.values()
				.stream()
				.filter(e -> !e.requiresPrompt())
				.sorted(Comparator.comparing(e -> -e.specificity()))
				.findFirst()
				.orElseThrow();
	}

	default Object doAction(Target target, ActionName name, ActionContext context) {
		ActionEntry action = findAction(target, name, context);
		return action.get(false);
	}

	default boolean doThreadAction(TraceThread thread, ActionName name) {
		if (thread == null) {
			return false;
		}
		Target target = getTargetService().getTarget(thread.getTrace());
		try {
			doAction(target, name, createContext(thread));
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	default boolean doTraceAction(Trace trace, ActionName name) {
		if (trace == null) {
			return false;
		}
		Target target = getTargetService().getTarget(trace);
		try {
			doAction(target, name, createContext(trace));
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	/**
	 * Step the given thread, stepping into subroutines
	 * 
	 * @param thread the thread to step
	 * @return true if successful, false otherwise
	 */
	default boolean stepInto(TraceThread thread) {
		return doThreadAction(thread, ActionName.STEP_INTO);
	}

	/**
	 * Step the current thread, stepping into subroutines
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean stepInto() {
		return stepInto(getCurrentThread());
	}

	/**
	 * Step the given thread, stepping over subroutines
	 * 
	 * @param thread the thread to step
	 * @return true if successful, false otherwise
	 */
	default boolean stepOver(TraceThread thread) {
		return doThreadAction(thread, ActionName.STEP_OVER);
	}

	/**
	 * Step the current thread, stepping over subroutines
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean stepOver() {
		return stepOver(getCurrentThread());
	}

	/**
	 * Step the given thread, until it returns from the current subroutine
	 * 
	 * @param thread the thread to step
	 * @return true if successful, false otherwise
	 */
	default boolean stepOut(TraceThread thread) {
		return doThreadAction(thread, ActionName.STEP_OUT);
	}

	/**
	 * Step the current thread, until it returns from the current subroutine
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean stepOut() {
		return stepOut(getCurrentThread());
	}

	/**
	 * Resume execution of the live target for the given trace thread
	 * 
	 * <p>
	 * This is commonly called "continue" or "go," as well.
	 * 
	 * @param thread the thread
	 * @return true if successful, false otherwise
	 */
	default boolean resume(TraceThread thread) {
		return doThreadAction(thread, ActionName.RESUME);
	}

	/**
	 * Resume execution of the live target for the given trace
	 * 
	 * <p>
	 * This is commonly called "continue" or "go," as well.
	 * 
	 * @param trace the trace
	 * @return true if successful, false otherwise
	 */
	default boolean resume(Trace trace) {
		return doTraceAction(trace, ActionName.RESUME);
	}

	/**
	 * Resume execution of the current thread or trace
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean resume() {
		if (resume(getCurrentThread())) {
			return true;
		}
		return resume(getCurrentTrace());
	}

	/**
	 * Interrupt execution of the live target for the given trace thread
	 * 
	 * <p>
	 * This is commonly called "pause" or "break," as well, but not "stop."
	 * 
	 * @param thread the thread to interrupt (may interrupt the whole target)
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt(TraceThread thread) {
		return doThreadAction(thread, ActionName.INTERRUPT);
	}

	/**
	 * Interrupt execution of the live target for the given trace
	 * 
	 * <p>
	 * This is commonly called "pause" or "break," as well, but not "stop."
	 * 
	 * @param trace the trace whose target to interrupt
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt(Trace trace) {
		return doTraceAction(trace, ActionName.INTERRUPT);
	}

	/**
	 * Interrupt execution of the current thread or trace
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt() {
		if (interrupt(getCurrentThread())) {
			return true;
		}
		return interrupt(getCurrentTrace());
	}

	/**
	 * Terminate execution of the live target for the given trace thread
	 * 
	 * <p>
	 * This is commonly called "stop" as well.
	 * 
	 * @param thread the thread to kill (may kill the whole target)
	 * @return true if successful, false otherwise
	 */
	default boolean kill(TraceThread thread) {
		return doThreadAction(thread, ActionName.KILL);
	}

	/**
	 * Terminate execution of the live target for the given trace
	 * 
	 * <p>
	 * This is commonly called "stop" as well.
	 * 
	 * @param trace the trace whose target to kill
	 * @return true if successful, false otherwise
	 */
	default boolean kill(Trace trace) {
		return doTraceAction(trace, ActionName.KILL);
	}

	/**
	 * Terminate execution of the current thread or trace
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean kill() {
		if (kill(getCurrentThread())) {
			return true;
		}
		return kill(getCurrentTrace());
	}

	/**
	 * Get the current state of the given trace
	 * 
	 * <p>
	 * If the trace does not have a live target, it is considered
	 * {@link TargetExecutionState#TERMINATED} (even if the trace <em>never</em> technically had a
	 * live target.) Otherwise, this gets the state of that live target. <b>NOTE:</b> This does not
	 * consider the current snap. It only considers a live target in the present.
	 * 
	 * @param trace the trace
	 * @return the trace's execution state
	 */
	default TargetExecutionState getExecutionState(Trace trace) {
		Target target = getTargetService().getTarget(trace);
		if (target == null) {
			return TargetExecutionState.TERMINATED;
		}
		// Use resume action's enablement as a proxy for state
		// This should work for recorder or rmi targets
		ActionEntry action = findAction(target, ActionName.RESUME, createContext(trace));
		if (action == null) {
			return TargetExecutionState.ALIVE;
		}
		return action.isEnabled() ? TargetExecutionState.STOPPED : TargetExecutionState.RUNNING;
	}

	/**
	 * Get the current state of the given thread
	 * 
	 * <p>
	 * If the thread does not have a corresponding live target thread, it is considered
	 * {@link TargetExecutionState#TERMINATED} (even if the thread <em>never</em> technically had a
	 * live target thread.) Otherwise, this gets the state of that live target thread. <b>NOTE:</b>
	 * This does not consider the current snap. It only considers a live target thread in the
	 * present. In other words, if the user rewinds trace history to a point where the thread was
	 * alive, this method still considers that thread terminated. To compute state with respect to
	 * trace history, use {@link TraceThread#getLifespan()} and check if it contains the current
	 * snap.
	 * 
	 * @param thread
	 * @return the thread's execution state
	 */
	default TargetExecutionState getExecutionState(TraceThread thread) {
		DebuggerCoordinates coords = getTraceManager().getCurrentFor(thread.getTrace());
		if (!coords.isAlive()) {
			return TargetExecutionState.TERMINATED;
		}
		return coords.getTarget().getThreadExecutionState(thread);
	}

	/**
	 * Check if the given trace's target is alive
	 * 
	 * @param trace the trace
	 * @return true if alive
	 */
	default boolean isTargetAlive(Trace trace) {
		return getExecutionState(trace).isAlive();
	}

	/**
	 * Check if the current target is alive
	 * 
	 * <p>
	 * <b>NOTE:</b> To be "current," the target must be recorded, and its trace must be the current
	 * trace.
	 * 
	 * @return true if alive
	 */
	default boolean isTargetAlive() {
		return isTargetAlive(requireCurrentTrace());
	}

	/**
	 * Check if the given trace thread's target is alive
	 * 
	 * @param thread the thread
	 * @return true if alive
	 */
	default boolean isThreadAlive(TraceThread thread) {
		return getExecutionState(thread).isAlive();
	}

	/**
	 * Check if the current target thread is alive
	 * 
	 * <p>
	 * <b>NOTE:</b> To be the "current" target thread, the target must be recorded, and its trace
	 * thread must be the current thread.
	 * 
	 * @return true if alive
	 */
	default boolean isThreadAlive() {
		return isThreadAlive(requireThread(getCurrentThread()));
	}

	/**
	 * Wait for the trace's target to break
	 * 
	 * <p>
	 * If the trace has no target, this method returns immediately, i.e., it assumes the target has
	 * terminated.
	 * 
	 * @param trace the trace
	 * @param timeout the maximum amount of time to wait
	 * @param unit the units for time
	 * @throws TimeoutException if the timeout expires
	 */
	default void waitForBreak(Trace trace, long timeout, TimeUnit unit) throws TimeoutException {
		if (!getExecutionState(trace).isRunning()) {
			return;
		}
		var listener = new DomainObjectListener() {
			CompletableFuture<Void> future = new CompletableFuture<>();

			@Override
			public void domainObjectChanged(DomainObjectChangedEvent ev) {
				if (!getExecutionState(trace).isRunning()) {
					future.complete(null);
				}
			}
		};
		trace.addListener(listener);
		try {
			if (!getExecutionState(trace).isRunning()) {
				return;
			}
			listener.future.get(timeout, unit);
		}
		catch (ExecutionException | InterruptedException e) {
			throw new RuntimeException(e);
		}
		finally {
			trace.removeListener(listener);
		}
	}

	/**
	 * Wait for the current target to break
	 * 
	 * @see #waitForBreak(Trace, long, TimeUnit)
	 * @param timeout the maximum
	 * @param unit the units for time
	 * @throws TimeoutException if the timeout expires
	 * @throws IllegalStateException if there is no current trace
	 */
	default void waitForBreak(long timeout, TimeUnit unit) throws TimeoutException {
		waitForBreak(requireCurrentTrace(), timeout, unit);
	}

	/**
	 * Execute a command on the live debugger for the given trace, capturing the output
	 * 
	 * @param trace the trace
	 * @param command the command
	 * @return the output, or null if there is no live interpreter
	 */
	default String executeCapture(Trace trace, String command) {
		Target target = getTargetService().getTarget(trace);
		return target.execute(command, true);
	}

	/**
	 * Execute a command on the live debugger for the current trace, capturing the output
	 * 
	 * @param command the command
	 * @return the output, or null if there is no live interpreter
	 * @throws IllegalStateException if there is no current trace
	 */
	default String executeCapture(String command) {
		return executeCapture(requireCurrentTrace(), command);
	}

	/**
	 * Execute a command on the live debugger for the given trace
	 * 
	 * @param trace the trace
	 * @param command the command
	 * @return true if successful
	 */
	default boolean execute(Trace trace, String command) {
		Target target = getTargetService().getTarget(trace);
		try {
			target.execute(command, false);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	/**
	 * Execute a command on the live debugger for the current trace
	 * 
	 * @param command the command
	 * @return true if successful
	 * @throws IllegalStateException if there is no current trace
	 */
	default boolean execute(String command) {
		return execute(requireCurrentTrace(), command);
	}

	/**
	 * Get the breakpoint service
	 * 
	 * @return the service
	 */
	default DebuggerLogicalBreakpointService getBreakpointService() {
		return requireService(DebuggerLogicalBreakpointService.class);
	}

	/**
	 * Create a static location at the given address in the current program
	 * 
	 * @param program the (static) program
	 * @param address the address
	 * @return the location
	 */
	default ProgramLocation staticLocation(Program program, Address address) {
		if (program instanceof TraceProgramView) {
			throw new IllegalArgumentException("The given program is dynamic, i.e., a trace view");
		}
		return new ProgramLocation(program, address);
	}

	/**
	 * Create a static location at the given address in the current program
	 * 
	 * @param program the (static) program
	 * @param addrString the address string
	 * @return the location
	 */
	default ProgramLocation staticLocation(Program program, String addrString) {
		return staticLocation(program, program.getAddressFactory().getAddress(addrString));
	}

	/**
	 * Create a static location at the given address in the current program
	 * 
	 * @param address the address
	 * @return the location
	 */
	default ProgramLocation staticLocation(Address address) {
		return staticLocation(requireCurrentProgram(), address);
	}

	/**
	 * Create a static location at the given address in the current program
	 * 
	 * @param addrString the address string
	 * @return the location
	 */
	default ProgramLocation staticLocation(String addrString) {
		return staticLocation(requireCurrentProgram(), addrString);
	}

	/**
	 * Create a dynamic location at the given address in the given view
	 * 
	 * @param view the (dynamic) trace view
	 * @param address the address
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(TraceProgramView view, Address address) {
		return new ProgramLocation(view, address);
	}

	/**
	 * Create a dynamic location at the given address in the given view
	 * 
	 * @param view the (dynamic) trace view
	 * @param addrString the address string
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(TraceProgramView view, String addrString) {
		return new ProgramLocation(view, view.getAddressFactory().getAddress(addrString));
	}

	/**
	 * Create a dynamic location at the given address in the current trace and snap
	 * 
	 * @param address the address
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(Address address) {
		return dynamicLocation(requireCurrentView(), address);
	}

	/**
	 * Create a dynamic location at the given address in the current trace and snap
	 * 
	 * @param addrString the address string
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(String addrString) {
		return dynamicLocation(requireCurrentView(), addrString);
	}

	/**
	 * Create a dynamic location at the given address in the given trace's primary view
	 * 
	 * @param trace the trace
	 * @param address the address
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(Trace trace, Address address) {
		return dynamicLocation(trace.getProgramView(), address);
	}

	/**
	 * Create a dynamic location at the given address in the given trace's primary view
	 * 
	 * @param trace the trace
	 * @param addrString the address string
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(Trace trace, String addrString) {
		return dynamicLocation(trace.getProgramView(), addrString);
	}

	/**
	 * Create a dynamic location at the given address in the given trace at the given snap
	 * 
	 * @param trace the trace
	 * @param snap the snap
	 * @param address the address
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(Trace trace, long snap, Address address) {
		return dynamicLocation(trace.getFixedProgramView(snap), address);
	}

	/**
	 * Create a dynamic location at the given address in the given trace at the given snap
	 * 
	 * @param trace the trace
	 * @param snap the snap
	 * @param addrString the address string
	 * @return the location
	 */
	default ProgramLocation dynamicLocation(Trace trace, long snap, String addrString) {
		return dynamicLocation(trace.getFixedProgramView(snap), addrString);
	}

	/**
	 * Get all the breakpoints
	 * 
	 * <p>
	 * This returns all logical breakpoints among all open programs and traces (targets)
	 * 
	 * @return the breakpoints
	 */
	default Set<LogicalBreakpoint> getAllBreakpoints() {
		return getBreakpointService().getAllBreakpoints();
	}

	/**
	 * Get the breakpoints in the given program, indexed by address
	 * 
	 * @param program the program
	 * @return the address-breakpoint-set map
	 */
	default NavigableMap<Address, Set<LogicalBreakpoint>> getBreakpoints(Program program) {
		return getBreakpointService().getBreakpoints(program);
	}

	/**
	 * Get the breakpoints in the given trace, indexed by (dynamic) address
	 * 
	 * @param trace the trace
	 * @return the address-breakpoint-set map
	 */
	default NavigableMap<Address, Set<LogicalBreakpoint>> getBreakpoints(Trace trace) {
		return getBreakpointService().getBreakpoints(trace);
	}

	/**
	 * Get the breakpoints at a given location
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @return the (possibly empty) set of breakpoints at that location
	 */
	default Set<LogicalBreakpoint> getBreakpointsAt(ProgramLocation location) {
		return getBreakpointService().getBreakpointsAt(location);
	}

	/**
	 * Get the breakpoints having the given name (from any open program or trace)
	 * 
	 * @param name the name
	 * @return the breakpoints
	 */
	default Set<LogicalBreakpoint> getBreakpointsNamed(String name) {
		return getBreakpointService().getAllBreakpoints()
				.stream()
				.filter(bp -> name.equals(bp.getName()))
				.collect(Collectors.toSet());
	}

	/**
	 * Class that implements {@link FlatDebuggerAPI#expectBreakpointChanges()}
	 */
	public static class ExpectingBreakpointChanges implements AutoCloseable {
		private final FlatDebuggerAPI flat;
		private final CompletableFuture<Void> changesSettled;

		public ExpectingBreakpointChanges(FlatDebuggerAPI flat,
				DebuggerLogicalBreakpointService service) {
			this.flat = flat;
			this.changesSettled = service.changesSettled();
		}

		@Override
		public void close() throws InterruptedException, ExecutionException, TimeoutException {
			Swing.allowSwingToProcessEvents();
			flat.waitOn(changesSettled);
		}
	}

	/**
	 * Perform some operations expected to cause changes, and then wait for those changes to settle
	 * 
	 * <p>
	 * Use this via a try-with-resources block containing the operations causing changes.
	 * 
	 * @return a closable object for a try-with-resources block
	 */
	default ExpectingBreakpointChanges expectBreakpointChanges() {
		return new ExpectingBreakpointChanges(this, getBreakpointService());
	}

	/**
	 * Toggle the breakpoints at a given location
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @return the (possibly empty) set of breakpoints at that location, or null if failed
	 */
	default Set<LogicalBreakpoint> breakpointsToggle(ProgramLocation location) {
		DebuggerLogicalBreakpointService service = getBreakpointService();
		try (ExpectingBreakpointChanges exp = expectBreakpointChanges()) {
			return waitOn(service.toggleBreakpointsAt(location,
				() -> CompletableFuture.completedFuture(Set.of())));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
	}

	/**
	 * Set a breakpoint at the given location
	 * 
	 * <p>
	 * <b>NOTE:</b> Many asynchronous events take place when creating a breakpoint, esp., among
	 * several live targets. Furthermore, some targets may adjust the breakpoint specification just
	 * slightly. This method does its best to identify the resulting breakpoint(s) once things have
	 * settled. Namely, it retrieves breakpoints at the specific location having the specified name
	 * and assumes those are the result. It is possible this command succeeds, but this method fails
	 * to identify the result. In that case, the returned result will be the empty set.
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @param length the length, for "access breakpoints" or "watchpoints"
	 * @param kinds the kinds, not all combinations are reasonable
	 * @param name a user-defined name
	 * @return the resulting breakpoint(s), or null if failed
	 */
	default Set<LogicalBreakpoint> breakpointSet(ProgramLocation location, long length,
			TraceBreakpointKindSet kinds, String name) {
		DebuggerLogicalBreakpointService service = getBreakpointService();
		try (ExpectingBreakpointChanges exp = expectBreakpointChanges()) {
			waitOn(service.placeBreakpointAt(location, length, kinds, name));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
		return service.getBreakpointsAt(location)
				.stream()
				.filter(b -> Objects.equals(name, b.getName()))
				.collect(Collectors.toSet());
	}

	/**
	 * Set a software breakpoint at the given location
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @param name a user-defined name
	 * @return true if successful
	 */
	default Set<LogicalBreakpoint> breakpointSetSoftwareExecute(ProgramLocation location,
			String name) {
		return breakpointSet(location, 1, TraceBreakpointKindSet.SW_EXECUTE, name);
	}

	/**
	 * Set a hardware breakpoint at the given location
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @param name a user-defined name
	 * @return true if successful
	 */
	default Set<LogicalBreakpoint> breakpointSetHardwareExecute(ProgramLocation location,
			String name) {
		return breakpointSet(location, 1, TraceBreakpointKindSet.HW_EXECUTE, name);
	}

	/**
	 * Set a read breakpoint at the given location
	 * 
	 * <p>
	 * This might also be called a "read watchpoint" or a "read access breakpoint."
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @param length the length
	 * @param name a user-defined name
	 * @return true if successful
	 */
	default Set<LogicalBreakpoint> breakpointSetRead(ProgramLocation location, int length,
			String name) {
		return breakpointSet(location, length, TraceBreakpointKindSet.READ, name);
	}

	/**
	 * Set a write breakpoint at the given location
	 * 
	 * <p>
	 * This might also be called a "write watchpoint" or a "write access breakpoint."
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @param length the length
	 * @param name a user-defined name
	 * @return true if successful
	 */
	default Set<LogicalBreakpoint> breakpointSetWrite(ProgramLocation location, int length,
			String name) {
		return breakpointSet(location, length, TraceBreakpointKindSet.WRITE, name);
	}

	/**
	 * Set an access breakpoint at the given location
	 * 
	 * <p>
	 * This might also be called a "watchpoint."
	 * 
	 * @param location the location, e.g., from {@link #staticLocation(String)} and
	 *            {@link #dynamicLocation(String)}.
	 * @param length the length
	 * @param name a user-defined name
	 * @return true if successful
	 */
	default Set<LogicalBreakpoint> breakpointSetAccess(ProgramLocation location, int length,
			String name) {
		return breakpointSet(location, length, TraceBreakpointKindSet.ACCESS, name);
	}

	/**
	 * If the location is dynamic, get its trace
	 * 
	 * @param location the location
	 * @return the trace, or null if a static location
	 */
	default Trace getTrace(ProgramLocation location) {
		Program program = location.getProgram();
		if (program instanceof TraceProgramView view) {
			return view.getTrace();
		}
		return null;
	}

	/**
	 * Enable the breakpoints at a given location
	 * 
	 * @param location the location, can be static or dynamic
	 * @return the (possibly empty) set of breakpoints at that location, or null if failed
	 */
	default Set<LogicalBreakpoint> breakpointsEnable(ProgramLocation location) {
		DebuggerLogicalBreakpointService service = getBreakpointService();
		Set<LogicalBreakpoint> col = service.getBreakpointsAt(location);
		try (ExpectingBreakpointChanges exp = expectBreakpointChanges()) {
			waitOn(service.enableAll(col, getTrace(location)));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
		return col;
	}

	/**
	 * Disable the breakpoints at a given location
	 * 
	 * @param location the location, can be static or dynamic
	 * @return the (possibly empty) set of breakpoints at that location, or null if failed
	 */
	default Set<LogicalBreakpoint> breakpointsDisable(ProgramLocation location) {
		DebuggerLogicalBreakpointService service = getBreakpointService();
		Set<LogicalBreakpoint> col = service.getBreakpointsAt(location);
		try (ExpectingBreakpointChanges exp = expectBreakpointChanges()) {
			waitOn(service.disableAll(col, getTrace(location)));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
		return col;
	}

	/**
	 * Clear the breakpoints at a given location
	 * 
	 * @param location the location, can be static or dynamic
	 * @return true if successful, false otherwise
	 */
	default boolean breakpointsClear(ProgramLocation location) {
		DebuggerLogicalBreakpointService service = getBreakpointService();
		Set<LogicalBreakpoint> col = service.getBreakpointsAt(location);
		try (ExpectingBreakpointChanges exp = expectBreakpointChanges()) {
			waitOn(service.deleteAll(col, getTrace(location)));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Flush each stage of the asynchronous processing pipelines from end to end
	 * 
	 * <p>
	 * This method includes as many components as its author knows to flush. It flushes the trace's
	 * event queue. Then, it waits for various services' changes to settle, in dependency order.
	 * Currently, that is the static mapping service followed by the logical breakpoint service.
	 * Note that some stages use timeouts. It's also possible the target had not generated all the
	 * expected events by the time this method began flushing its queue. Thus, callers should still
	 * check that some expected condition is met and possibly repeat the flush before proceeding.
	 * 
	 * <p>
	 * There are additional dependents in the GUI; however, scripts should not depend on them, so we
	 * do not wait on them.
	 * 
	 * @param trace the trace whose events need to be completely processed before continuing.
	 * @return true if all stages were flushed, false if there were errors
	 */
	default boolean flushAsyncPipelines(Trace trace) {
		try {
			trace.flushEvents();
			waitOn(getMappingService().changesSettled());
			waitOn(getBreakpointService().changesSettled());
			Swing.allowSwingToProcessEvents();
			return true;
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
	}

	// TODO: Interaction with the target process itself, e.g., via stdio.
}
