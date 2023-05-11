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
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.util.PathUtils;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.program.TraceProgramView;
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
	 * @see #goToDynamic(ProgramLocation)
	 */
	default boolean goToDynamic(Address address) {
		return goToDynamic(dynamicLocation(address));
	}

	/**
	 * Go to the given dynamic address in the dynamic listing
	 * 
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
		Trace trace = null;
		try {
			trace = ProgramEmulationUtils.launchEmulationTrace(program, address, this);
			DebuggerTraceManagerService traceManager = getTraceManager();
			traceManager.openTrace(trace);
			traceManager.activateTrace(trace);
			Swing.allowSwingToProcessEvents();
		}
		finally {
			if (trace != null) {
				trace.release(this);
			}
		}
		return trace;
	}

	/**
	 * Does the same as {@link #emulateLaunch(Program, Address)}, for the current program
	 * 
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
	 * Copy memory from target to trace, if applicable and not already cached
	 * 
	 * @param trace the trace to update
	 * @param snap the snap the snap, to determine whether target bytes are applicable
	 * @param start the starting address
	 * @param length the number of bytes to make fresh
	 * @throws InterruptedException if the operation is interrupted
	 * @throws ExecutionException if an error occurs
	 * @throws TimeoutException if the operation times out
	 */
	default void refreshMemoryIfLive(Trace trace, long snap, Address start, int length,
			TaskMonitor monitor) throws InterruptedException, ExecutionException, TimeoutException {
		TraceRecorder recorder = getModelService().getRecorder(trace);
		if (recorder == null) {
			return;
		}
		if (recorder.getSnap() != snap) {
			return;
		}
		waitOn(recorder.readMemoryBlocks(new AddressSet(safeRange(start, length)), monitor));
		waitOn(recorder.getTarget().getModel().flushEvents());
		waitOn(recorder.flushTransactions());
		trace.flushEvents();
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
	 */
	default int readMemory(Trace trace, long snap, Address start, byte[] buffer,
			TaskMonitor monitor) {
		try {
			refreshMemoryIfLive(trace, snap, start, buffer.length, monitor);
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return 0;
		}

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
	 */
	default byte[] readMemory(Trace trace, long snap, Address start, int length,
			TaskMonitor monitor) {
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
	 * @return the number of bytes read
	 */
	default int readMemory(Address start, byte[] buffer, TaskMonitor monitor) {
		TraceProgramView view = requireCurrentView();
		return readMemory(view.getTrace(), view.getSnap(), start, buffer, monitor);
	}

	/**
	 * Read memory for the current trace view, refreshing from target if needed
	 * 
	 * @param start the starting address
	 * @param length the desired number of bytes
	 * @return the array of bytes read, can be shorter than desired
	 */
	default byte[] readMemory(Address start, int length, TaskMonitor monitor) {
		TraceProgramView view = requireCurrentView();
		return readMemory(view.getTrace(), view.getSnap(), start, length, monitor);
	}

	/**
	 * Search trace memory for a given masked byte sequence
	 * 
	 * <p>
	 * <b>NOTE:</b> This searches the trace only. It will not interrogate the live target. There are
	 * two mechanisms for searching a live target's full memory: 1) Capture the full memory (or the
	 * subset to search) -- using, e.g., {@link #refreshMemoryIfLive(Trace, long, Address, int)} --
	 * then search the trace. 2) If possible, invoke the target debugger's search functions --
	 * using, e.g., {@link #executeCapture(String)}.
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
	 * @throws InterruptedException if the operation is interrupted
	 * @throws ExecutionException if an error occurs
	 * @throws TimeoutException if the operation times out
	 */
	default void refreshRegistersIfLive(TracePlatform platform, TraceThread thread, int frame,
			long snap, Collection<Register> registers)
			throws InterruptedException, ExecutionException, TimeoutException {
		Trace trace = thread.getTrace();
		TraceRecorder recorder = getModelService().getRecorder(trace);
		if (recorder == null) {
			return;
		}
		if (recorder.getSnap() != snap) {
			return;
		}
		Set<Register> asSet =
			registers instanceof Set<?> ? (Set<Register>) registers : Set.copyOf(registers);
		waitOn(recorder.captureThreadRegisters(platform, thread, frame, asSet));
		waitOn(recorder.getTarget().getModel().flushEvents());
		waitOn(recorder.flushTransactions());
		trace.flushEvents();
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
		try {
			refreshRegistersIfLive(platform, thread, frame, snap, registers);
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
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
	 * @see #readRegisters(TraceThread, int, long, Collection)
	 * @return the register's value, or null on error
	 */
	default RegisterValue readRegister(TracePlatform platform, TraceThread thread, int frame,
			long snap, Register register) {
		List<RegisterValue> result = readRegisters(platform, thread, frame, snap, Set.of(register));
		return result == null ? null : result.get(0);
	}

	/**
	 * Read several registers from the current context, refreshing from the target if needed
	 * 
	 * @see #readRegisters(TraceThread, int, long, Collection)
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
	 * @see #readRegisters(TraceThread, int, long, Collection)
	 * @throws IllegalArgumentException if any name is invalid
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
	 * @see #readRegister(Register)
	 * @throws IllegalArgumentException if the name is invalid
	 */
	default RegisterValue readRegister(String name) {
		TracePlatform platform = requireCurrentPlatform();
		Register register = validateRegisterName(platform.getLanguage(), name);
		return readRegister(platform, register);
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
	 * control mode for the trace. See {@link #setControlMode(ControlMode)}. In read-only mode,
	 * this will always fail. When editing traces, a write almost always succeeds. Exceptions would
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
	 * control mode for the trace. See {@link #setControlMode(ControlMode)}. In read-only mode,
	 * this will always fail. When editing traces, a write almost always succeeds. Exceptions would
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
	 * @see #writeRegister(TraceThread, int, long, RegisterValue)
	 * @throws IllegalArgumentException if the register name is invalid
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
	 * @param mode specifies in what way to apply the patch
	 * @param rv the register value
	 * @return true if successful, false otherwise
	 */
	default boolean writeRegister(RegisterValue rv) {
		return writeRegister(createStateEditor(), rv);
	}

	/**
	 * Patch a register of the current thread, according to the current control mode
	 * 
	 * @see #writeRegister(RegisterValue)
	 * @throws IllegalArgumentException if the register name is invalid
	 */
	default boolean writeRegister(String name, BigInteger value) {
		return writeRegister(new RegisterValue(
			validateRegisterName(requireCurrentTrace().getBaseLanguage(), name), value));
	}

	/**
	 * Get the recorder for the current target
	 * 
	 * <p>
	 * If the current trace is not live, this returns null.
	 * 
	 * @return the recorder, or null
	 */
	default TraceRecorder getCurrentRecorder() {
		return getTraceManager().getCurrent().getRecorder();
	}

	/**
	 * Get the model (target) service
	 * 
	 * @return the service
	 */
	default DebuggerModelService getModelService() {
		return requireService(DebuggerModelService.class);
	}

	/**
	 * Get offers for launching the given program
	 * 
	 * @param program the program
	 * @return the offers
	 */
	default List<DebuggerProgramLaunchOffer> getLaunchOffers(Program program) {
		return getModelService().getProgramLaunchOffers(program).collect(Collectors.toList());
	}

	/**
	 * Get offers for launching the current program
	 * 
	 * @return the offers
	 */
	default List<DebuggerProgramLaunchOffer> getLaunchOffers() {
		return getLaunchOffers(requireCurrentProgram());
	}

	/**
	 * Get the best launch offer for a program, throwing an exception if there is no offer
	 * 
	 * @param program the program
	 * @return the offer
	 * @throws NoSuchElementException if there is no offer
	 */
	default DebuggerProgramLaunchOffer requireLaunchOffer(Program program) {
		Optional<DebuggerProgramLaunchOffer> offer =
			getModelService().getProgramLaunchOffers(program).findFirst();
		if (offer.isEmpty()) {
			throw new NoSuchElementException("No offers to launch " + program);
		}
		return offer.get();
	}

	/**
	 * Launch the given offer, overriding its command line
	 * 
	 * <p>
	 * <b>NOTE:</b> Most offers take a command line, but not all do. If this is used for an offer
	 * that does not, it's behavior is undefined.
	 * 
	 * <p>
	 * Launches are not always successful, and may in fact fail frequently, usually because of
	 * configuration errors or missing components on the target platform. This may leave stale
	 * connections and/or target debuggers, processes, etc., in strange states. Furthermore, even if
	 * launching the target is successful, starting the recorder may not succeed, typically because
	 * Ghidra cannot identify and map the target platform to a Sleigh language. This method makes no
	 * attempt at cleaning up partial pieces. Instead it returns those pieces in the launch result.
	 * If the result includes a recorder, the launch was successful. If not, the script can decide
	 * what to do with the other pieces. That choice depends on what is expected of the user. Can
	 * the user reasonable be expected to intervene and complete the launch manually? How many
	 * targets does the script intend to launch? How big is the mess if left partially completed?
	 * 
	 * @param offer the offer (this includes the program given when asking for offers)
	 * @param commandLine the command-line override. If this doesn't refer to the same program as
	 *            the offer, there may be unexpected results
	 * @param monitor the monitor for the launch stages
	 * @return the result, possibly partial
	 */
	default LaunchResult launch(DebuggerProgramLaunchOffer offer, String commandLine,
			TaskMonitor monitor) {
		try {
			return waitOn(offer.launchProgram(monitor, PromptMode.NEVER, new LaunchConfigurator() {
				@Override
				public Map<String, ?> configureLauncher(TargetLauncher launcher,
						Map<String, ?> arguments, RelPrompt relPrompt) {
					Map<String, Object> adjusted = new HashMap<>(arguments);
					adjusted.put(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, commandLine);
					return adjusted;
				}
			}));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			// TODO: This is not ideal, since it's likely partially completed
			return LaunchResult.totalFailure(e);
		}
	}

	/**
	 * Launch the given offer with the default/saved arguments
	 * 
	 * @see #launch(DebuggerProgramLaunchOffer, String, TaskMonitor)
	 */
	default LaunchResult launch(DebuggerProgramLaunchOffer offer, TaskMonitor monitor) {
		try {
			return waitOn(offer.launchProgram(monitor, PromptMode.NEVER));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			// TODO: This is not ideal, since it's likely partially completed
			return LaunchResult.totalFailure(e);
		}
	}

	/**
	 * Launch the given program, overriding its command line
	 * 
	 * <p>
	 * This takes the best offer for the given program. The command line should invoke the given
	 * program. If it does not, there may be unexpected results.
	 * 
	 * @see #launch(DebuggerProgramLaunchOffer, String, TaskMonitor)
	 */
	default LaunchResult launch(Program program, String commandLine, TaskMonitor monitor)
			throws InterruptedException, ExecutionException, TimeoutException {
		return launch(requireLaunchOffer(program), commandLine, monitor);
	}

	/**
	 * Launch the given program with the default/saved arguments
	 * 
	 * <p>
	 * This takes the best offer for the given program.
	 * 
	 * @see #launch(DebuggerProgramLaunchOffer, String, TaskMonitor)
	 */
	default LaunchResult launch(Program program, TaskMonitor monitor)
			throws InterruptedException, ExecutionException, TimeoutException {
		return launch(requireLaunchOffer(program), monitor);
	}

	/**
	 * Launch the current program, overriding its command line
	 * 
	 * @see #launch(Program, String, TaskMonitor)
	 */
	default LaunchResult launch(String commandLine, TaskMonitor monitor)
			throws InterruptedException, ExecutionException, TimeoutException {
		return launch(requireCurrentProgram(), commandLine, monitor);
	}

	/**
	 * Launch the current program with the default/saved arguments
	 * 
	 * @see #launch(Program, TaskMonitor)
	 */
	default LaunchResult launch(TaskMonitor monitor)
			throws InterruptedException, ExecutionException, TimeoutException {
		return launch(requireCurrentProgram(), monitor);
	}

	/**
	 * Get the target for a given trace
	 * 
	 * <p>
	 * WARNING: This method will likely change or be removed in the future.
	 * 
	 * @param trace the trace
	 * @return the target, or null if not alive
	 */
	default TargetObject getTarget(Trace trace) {
		TraceRecorder recorder = getModelService().getRecorder(trace);
		if (recorder == null) {
			return null;
		}
		return recorder.getTarget();
	}

	/**
	 * Get the target thread for a given trace thread
	 * 
	 * <p>
	 * WARNING: This method will likely change or be removed in the future.
	 * 
	 * @param thread the trace thread
	 * @return the target thread, or null if not alive
	 */
	default TargetThread getTargetThread(TraceThread thread) {
		TraceRecorder recorder = getModelService().getRecorder(thread.getTrace());
		if (recorder == null) {
			return null;
		}
		return recorder.getTargetThread(thread);
	}

	/**
	 * Get the user focus for a given trace
	 * 
	 * <p>
	 * WARNING: This method will likely change or be removed in the future.
	 * 
	 * @param trace the trace
	 * @return the target, or null if not alive
	 */
	default TargetObject getTargetFocus(Trace trace) {
		TraceRecorder recorder = getModelService().getRecorder(trace);
		if (recorder == null) {
			return null;
		}
		TargetObject focus = recorder.getFocus();
		return focus != null ? focus : recorder.getTarget();
	}

	/**
	 * Find the most suitable object related to the given object implementing the given interface
	 * 
	 * <p>
	 * WARNING: This method will likely change or be removed in the future.
	 * 
	 * @param <T> the interface type
	 * @param seed the seed object
	 * @param iface the interface class
	 * @return the related interface, or null
	 * @throws ClassCastException if the model violated its schema wrt. the requested interface
	 */
	@SuppressWarnings("unchecked")
	default <T extends TargetObject> T findInterface(TargetObject seed, Class<T> iface) {
		DebuggerObjectModel model = seed.getModel();
		List<String> found = model
				.getRootSchema()
				.searchForSuitable(iface, seed.getPath());
		if (found == null) {
			return null;
		}
		try {
			Object value = waitOn(model.fetchModelValue(found));
			return (T) value;
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
	}

	/**
	 * Find the most suitable object related to the given thread implementing the given interface
	 * 
	 * @param <T> the interface type
	 * @param thread the thread
	 * @param iface the interface class
	 * @return the related interface, or null
	 * @throws ClassCastException if the model violated its schema wrt. the requested interface
	 */
	default <T extends TargetObject> T findInterface(TraceThread thread, Class<T> iface) {
		TargetThread targetThread = getTargetThread(thread);
		if (targetThread == null) {
			return null;
		}
		return findInterface(targetThread, iface);
	}

	/**
	 * Find the most suitable object related to the given trace's focus implementing the given
	 * interface
	 * 
	 * @param <T> the interface type
	 * @param thread the thread
	 * @param iface the interface class
	 * @return the related interface, or null
	 * @throws ClassCastException if the model violated its schema wrt. the requested interface
	 */
	default <T extends TargetObject> T findInterface(Trace trace, Class<T> iface) {
		TargetObject focus = getTargetFocus(trace);
		if (focus == null) {
			return null;
		}
		return findInterface(focus, iface);
	}

	/**
	 * Find the interface related to the current thread or trace
	 * 
	 * <p>
	 * This first attempts to find the most suitable object related to the current trace thread. If
	 * that fails, or if there is no current thread, it tries to find the one related to the current
	 * trace (or its focus). If there is no current trace, this throws an exception.
	 * 
	 * @param <T> the interface type
	 * @param iface the interface class
	 * @return the related interface, or null
	 * @throws IllegalStateException if there is no current trace
	 */
	default <T extends TargetObject> T findInterface(Class<T> iface) {
		TraceThread thread = getCurrentThread();
		T t = thread == null ? null : findInterface(thread, iface);
		if (t != null) {
			return t;
		}
		return findInterface(requireCurrentTrace(), iface);
	}

	/**
	 * Step the given target object
	 * 
	 * @param steppable the steppable target object
	 * @param kind the kind of step to take
	 * @return true if successful, false otherwise
	 */
	default boolean step(TargetSteppable steppable, TargetStepKind kind) {
		if (steppable == null) {
			return false;
		}
		try {
			waitOn(steppable.step(kind));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Step the given thread on target according to the given kind
	 * 
	 * @param thread the trace thread
	 * @param kind the kind of step to take
	 * @return true if successful, false otherwise
	 */
	default boolean step(TraceThread thread, TargetStepKind kind) {
		if (thread == null) {
			return false;
		}
		return step(findInterface(thread, TargetSteppable.class), kind);
	}

	/**
	 * Step the current thread, stepping into subroutines
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean stepInto() {
		return step(findInterface(TargetSteppable.class), TargetStepKind.INTO);
	}

	/**
	 * Step the current thread, stepping over subroutines
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean stepOver() {
		return step(findInterface(TargetSteppable.class), TargetStepKind.OVER);
	}

	/**
	 * Step the current thread, until it returns from the current subroutine
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean stepOut() {
		return step(findInterface(TargetSteppable.class), TargetStepKind.FINISH);
	}

	/**
	 * Resume execution of the given target object
	 * 
	 * @param resumable the resumable target object
	 * @return true if successful, false otherwise
	 */
	default boolean resume(TargetResumable resumable) {
		if (resumable == null) {
			return false;
		}
		try {
			waitOn(resumable.resume());
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
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
		return resume(findInterface(thread, TargetResumable.class));
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
		return resume(findInterface(trace, TargetResumable.class));
	}

	/**
	 * Resume execution of the current thread or trace
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean resume() {
		TraceThread thread = getCurrentThread();
		TargetResumable resumable =
			thread == null ? null : findInterface(thread, TargetResumable.class);
		if (resumable == null) {
			resumable = findInterface(requireCurrentTrace(), TargetResumable.class);
		}
		return resume(resumable);
	}

	/**
	 * Interrupt execution of the given target object
	 * 
	 * @param interruptible the interruptible target object
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt(TargetInterruptible interruptible) {
		if (interruptible == null) {
			return false;
		}
		try {
			waitOn(interruptible.interrupt());
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Interrupt execution of the live target for the given trace thread
	 * 
	 * <p>
	 * This is commonly called "pause" or "break," as well, but not "stop."
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt(TraceThread thread) {
		return interrupt(findInterface(thread, TargetInterruptible.class));
	}

	/**
	 * Interrupt execution of the live target for the given trace
	 * 
	 * <p>
	 * This is commonly called "pause" or "break," as well, but not "stop."
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt(Trace trace) {
		return interrupt(findInterface(trace, TargetInterruptible.class));
	}

	/**
	 * Interrupt execution of the current thread or trace
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean interrupt() {
		return interrupt(findInterface(TargetInterruptible.class));
	}

	/**
	 * Terminate execution of the given target object
	 * 
	 * @param interruptible the interruptible target object
	 * @return true if successful, false otherwise
	 */
	default boolean kill(TargetKillable killable) {
		if (killable == null) {
			return false;
		}
		try {
			waitOn(killable.kill());
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Terminate execution of the live target for the given trace thread
	 * 
	 * <p>
	 * This is commonly called "stop" as well.
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean kill(TraceThread thread) {
		return kill(findInterface(thread, TargetKillable.class));
	}

	/**
	 * Terminate execution of the live target for the given trace
	 * 
	 * <p>
	 * This is commonly called "stop" as well.
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean kill(Trace trace) {
		return kill(findInterface(trace, TargetKillable.class));
	}

	/**
	 * Terminate execution of the current thread or trace
	 * 
	 * @return true if successful, false otherwise
	 */
	default boolean kill() {
		return kill(findInterface(TargetKillable.class));
	}

	/**
	 * Get the current state of the given target
	 * 
	 * <p>
	 * Any invalidated object is considered {@link TargetExecutionState#TERMINATED}. Otherwise, it's
	 * at least considered {@link TargetExecutionState#ALIVE}. A more specific state may be
	 * determined by searching the model for the conventionally-related object implementing
	 * {@link TargetObjectStateful}. This method applies this convention.
	 * 
	 * @param target the target object
	 * @return the target object's execution state
	 */
	default TargetExecutionState getExecutionState(TargetObject target) {
		if (!target.isValid()) {
			return TargetExecutionState.TERMINATED;
		}
		TargetExecutionStateful stateful = findInterface(target, TargetExecutionStateful.class);
		return stateful == null ? TargetExecutionState.ALIVE : stateful.getExecutionState();
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
	 * @return the trace's target's execution state
	 */
	default TargetExecutionState getExecutionState(Trace trace) {
		TargetObject target = getTarget(trace);
		if (target == null) {
			return TargetExecutionState.TERMINATED;
		}
		return getExecutionState(target);
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
	 * @return
	 */
	default TargetExecutionState getExecutionState(TraceThread thread) {
		TargetObject target = getTargetThread(thread);
		if (target == null) {
			return TargetExecutionState.TERMINATED;
		}
		return getExecutionState(target);
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
	 * @return
	 */
	default boolean isThreadAlive() {
		return isThreadAlive(requireThread(getCurrentThread()));
	}

	/**
	 * Waits for the given target to exit the {@link TargetExecutionState#RUNNING} state
	 * 
	 * <p>
	 * <b>NOTE:</b> There may be subtleties depending on the target debugger. For the most part, if
	 * the connection is handling a single target, things will work as expected. However, if there
	 * are multiple targets on one connection, it is possible for the given target to break, but for
	 * the target debugger to remain unresponsive to commands. This would happen, e.g., if a second
	 * target on the same connection is still running.
	 * 
	 * @param target the target
	 * @param timeout the maximum amount of time to wait
	 * @param unit the units for time
	 * @throws TimeoutException if the timeout expires
	 */
	default void waitForBreak(TargetObject target, long timeout, TimeUnit unit)
			throws TimeoutException {
		TargetExecutionStateful stateful = findInterface(target, TargetExecutionStateful.class);
		if (stateful == null) {
			throw new IllegalArgumentException("Given target is not stateful");
		}
		var listener = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			CompletableFuture<Void> future = new CompletableFuture<>();

			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			private void stateChanged(TargetObject parent, TargetExecutionState state) {
				if (parent == stateful && !state.isRunning()) {
					future.complete(null);
				}
			}
		};
		target.getModel().addModelListener(listener);
		try {
			if (!stateful.getExecutionState().isRunning()) {
				return;
			}
			listener.future.get(timeout, unit);
		}
		catch (ExecutionException | InterruptedException e) {
			throw new RuntimeException(e);
		}
		finally {
			target.getModel().removeModelListener(listener);
		}
	}

	/**
	 * Wait for the trace's target to break
	 * 
	 * <p>
	 * If the trace has no target, this method returns immediately, i.e., it assumes the target has
	 * terminated.
	 * 
	 * @see #waitForBreak(TargetObject, long, TimeUnit)
	 * @param trace the trace
	 * @param timeout the maximum amount of time to wait
	 * @param unit the units for time
	 * @throws TimeoutException if the timeout expires
	 */
	default void waitForBreak(Trace trace, long timeout, TimeUnit unit) throws TimeoutException {
		TargetObject target = getTarget(trace);
		if (target == null || !target.isValid()) {
			return;
		}
		waitForBreak(target, timeout, unit);
	}

	/**
	 * Wait for the current target to break
	 * 
	 * @see #waitForBreak(Trace, long, TimeUnit)
	 * @param timeout the maximum
	 * @param unit
	 * @param timeout the maximum amount of time to wait
	 * @param unit the units for time
	 * @throws TimeoutException if the timeout expires
	 * @throws IllegalStateException if there is no current trace
	 */
	default void waitForBreak(long timeout, TimeUnit unit) throws TimeoutException {
		waitForBreak(requireCurrentTrace(), timeout, unit);
	}

	/**
	 * Execute a command in a connection's interpreter, capturing the output
	 * 
	 * <p>
	 * This executes a raw command in the given interpreter. The command could have arbitrary
	 * effects, so it may be necessary to wait for those effects to be handled by the tool's
	 * services and plugins before proceeding.
	 * 
	 * @param interpreter the interpreter
	 * @param command the command
	 * @return the output, or null if there is no interpreter
	 */
	default String executeCapture(TargetInterpreter interpreter, String command) {
		if (interpreter == null) {
			return null;
		}
		try {
			return waitOn(interpreter.executeCapture(command));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
	}

	/**
	 * Execute a command on the live debugger for the given trace, capturing the output
	 * 
	 * @param trace the trace
	 * @param command the command
	 * @return the output, or null if there is no live interpreter
	 */
	default String executeCapture(Trace trace, String command) {
		return executeCapture(findInterface(trace, TargetInterpreter.class), command);
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
	 * Execute a command in a connection's interpreter
	 * 
	 * <p>
	 * This executes a raw command in the given interpreter. The command could have arbitrary
	 * effects, so it may be necessary to wait for those effects to be handled by the tool's
	 * services and plugins before proceeding.
	 * 
	 * @param interpreter the interpreter
	 * @param command the command
	 * @return true if successful
	 */
	default boolean execute(TargetInterpreter interpreter, String command) {
		if (interpreter == null) {
			return false;
		}
		try {
			waitOn(interpreter.executeCapture(command));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return false;
		}
		return true;
	}

	/**
	 * Execute a command on the live debugger for the given trace
	 * 
	 * @param trace the trace
	 * @param command the command
	 * @return true if successful
	 */
	default boolean execute(Trace trace, String command) {
		return execute(findInterface(trace, TargetInterpreter.class), command);
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
	 * @param program the program
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
		if (program instanceof TraceProgramView) {
			return ((TraceProgramView) program).getTrace();
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
	 * Get the value at the given path for the given model
	 * 
	 * @param model the model
	 * @param path the path
	 * @return the avlue, or null if the trace is not live or if the path does not exist
	 */
	default Object getModelValue(DebuggerObjectModel model, String path) {
		try {
			return waitOn(model.fetchModelValue(PathUtils.parse(path)));
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
	}

	/**
	 * Get the value at the given path for the current trace's model
	 * 
	 * @param path the path
	 * @return the value, or null if the trace is not live or if the path does not exist
	 */
	default Object getModelValue(String path) {
		TraceRecorder recorder = getModelService().getRecorder(getCurrentTrace());
		if (recorder == null) {
			return null;
		}
		return getModelValue(recorder.getTarget().getModel(), path);
	}

	/**
	 * Refresh the given objects children (elements and attributes)
	 * 
	 * @param object the object
	 * @return the set of children, excluding primitive-valued attributes
	 */
	default Set<TargetObject> refreshObjectChildren(TargetObject object) {
		try {
			// Refresh both children and memory/register values
			waitOn(object.invalidateCaches());
			waitOn(object.resync());
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			return null;
		}
		Set<TargetObject> result = new LinkedHashSet<>();
		result.addAll(object.getCachedElements().values());
		for (Object v : object.getCachedAttributes().values()) {
			if (v instanceof TargetObject) {
				result.add((TargetObject) v);
			}
		}
		return result;
	}

	/**
	 * Refresh the given object and its children, recursively
	 * 
	 * <p>
	 * The objects are traversed in depth-first pre-order. Links are traversed, even if the object
	 * is not part of the specified subtree, but an object is skipped if it has already been
	 * visited.
	 * 
	 * @param object the seed object
	 * @return true if the traversal completed successfully
	 */
	default boolean refreshSubtree(TargetObject object) {
		var util = new Object() {
			Set<TargetObject> visited = new HashSet<>();

			boolean visit(TargetObject object) {
				if (!visited.add(object)) {
					return true;
				}
				for (TargetObject child : refreshObjectChildren(object)) {
					if (!visit(child)) {
						return false;
					}
				}
				return true;
			}
		};
		return util.visit(object);
	}

	/**
	 * Flush each stage of the asynchronous processing pipelines from end to end
	 * 
	 * <p>
	 * This method includes as many components as its author knows to flush. If the given trace is
	 * alive, flushing starts with the connection's event queue, followed by the recorder's event
	 * and transaction queues. Next, it flushes the trace's event queue. Then, it waits for various
	 * services' changes to settle, in dependency order. Currently, that is the static mapping
	 * service followed by the logical breakpoint service. Note that some stages use timeouts. It's
	 * also possible the target had not generated all the expected events by the time this method
	 * began flushing its queue. Thus, callers should still check that some expected condition is
	 * met and possibly repeat the flush before proceeding.
	 * 
	 * <p>
	 * There are additional dependents, e.g., the breakpoint listing plugin; however, scripts should
	 * not depend on them, so we do not wait on them.
	 * 
	 * @param trace the trace whose events need to be completely processed before continuing.
	 * @return
	 */
	default boolean flushAsyncPipelines(Trace trace) {
		try {
			TraceRecorder recorder = getModelService().getRecorder(trace);
			if (recorder != null) {
				waitOn(recorder.getTarget().getModel().flushEvents());
				waitOn(recorder.flushTransactions());
			}
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
	// The DebugModel API does not currently support this.
}
