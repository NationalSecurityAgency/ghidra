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

import java.util.Collection;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.Scheduler.RunResult;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A service for accessing managed emulators.
 * 
 * <p>
 * Managed emulators are employed by the UI and trace manager to perform emulation requested by the
 * user. Scripts may interact with these managed emulators, or they may instantiate their own
 * unmanaged emulators, without using this service.
 */
@ServiceInfo(defaultProvider = DebuggerEmulationServicePlugin.class)
public interface DebuggerEmulationService {

	interface EmulationResult extends RunResult {
		/**
		 * Get the (scratch) snapshot where the emulated state is stored
		 * 
		 * @return the snapshot
		 */
		public long snapshot();
	}

	/**
	 * The result of letting the emulator "run free"
	 */
	record RecordEmulationResult(TraceSchedule schedule, long snapshot, Throwable error)
			implements EmulationResult {
	}

	/**
	 * An emulator managed by this service
	 */
	record CachedEmulator(Trace trace, DebuggerPcodeMachine<?> emulator) {
		/**
		 * Get the trace to which the emulator is bound
		 * 
		 * @return the trace
		 */
		@Override
		public Trace trace() {
			return trace;
		}

		/**
		 * Get the emulator
		 * 
		 * <p>
		 * <b>WARNING:</b> This emulator belongs to this service. You may interrupt it, but stepping
		 * it, or otherwise manipulating it without the service's knowledge can lead to unintended
		 * consequences.
		 * 
		 * @return the emulator
		 */
		@Override
		public DebuggerPcodeMachine<?> emulator() {
			return emulator;
		}
	}

	/**
	 * A listener for changes in emulator state
	 */
	interface EmulatorStateListener {
		/**
		 * An emulator is running
		 * 
		 * @param emu the emulator
		 */
		void running(CachedEmulator emu);

		/**
		 * An emulator has stopped
		 * 
		 * @param emu the emulator
		 */
		void stopped(CachedEmulator emu);
	}

	/**
	 * Get the available emulator factories
	 * 
	 * @return the collection of factories
	 */
	Collection<DebuggerPcodeEmulatorFactory> getEmulatorFactories();

	/**
	 * Set the current emulator factory
	 * 
	 * <p>
	 * TODO: Should this be set on a per-program, per-trace basis? Need to decide what is saved to
	 * the tool and what is saved to the program/trace. My inclination is to save current factory to
	 * the tool, but the config options for each factory to the program/trace.
	 * 
	 * <p>
	 * TODO: Should there be some opinion service for choosing default configs? Seems overly
	 * complicated for what it offers. For now, we won't save anything, we'll default to the
	 * (built-in) {@link BytesDebuggerPcodeEmulatorFactory}, and we won't have configuration
	 * options.
	 * 
	 * @param factory the chosen factory
	 */
	void setEmulatorFactory(DebuggerPcodeEmulatorFactory factory);

	/**
	 * Get the current emulator factory
	 * 
	 * @return the factory
	 */
	DebuggerPcodeEmulatorFactory getEmulatorFactory();

	/**
	 * Perform emulation to realize the machine state of the given time coordinates
	 * 
	 * <p>
	 * Only those address ranges actually modified during emulation are written into the scratch
	 * space. It is the responsibility of anyone reading from scratch space to retrieve state and/or
	 * annotations from the initial snap, when needed. The scratch snapshot is given the description
	 * "{@code emu:[time]}", where {@code [time]} is the given time parameter as a string.
	 * 
	 * <p>
	 * The service may use a cached emulator in order to realize the requested machine state. This
	 * is especially important to ensure that a user stepping forward does not incur ever increasing
	 * costs. On the other hand, the service should be careful to invalidate cached results when the
	 * recorded machine state in a trace changes.
	 * 
	 * @param platform the trace platform containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @param monitor a monitor for cancellation and progress reporting
	 * @return the snap in the trace's scratch space where the realized state is stored
	 * @throws CancelledException if the emulation is cancelled
	 */
	long emulate(TracePlatform platform, TraceSchedule time, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Emulate using the trace's "host" platform
	 * 
	 * @see #emulate(TracePlatform, TraceSchedule, TaskMonitor)
	 * @param trace the trace containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @param monitor a monitor for cancellation and progress reporting
	 * @return the snap in the trace's scratch space where the realize state is stored
	 * @throws CancelledException if the emulation is cancelled
	 */
	default long emulate(Trace trace, TraceSchedule time, TaskMonitor monitor)
			throws CancelledException {
		return emulate(trace.getPlatformManager().getHostPlatform(), time, monitor);
	}

	/**
	 * Allow the emulator to "run free" until it is interrupted or encounters an error
	 *
	 * <p>
	 * The service may perform some preliminary emulation to realize the machine's initial state. If
	 * the monitor cancels during preliminary emulation, this method throws a
	 * {@link CancelledException}. If the monitor cancels the emulation during the run, it is
	 * treated the same as interruption. The machine state will be written to the trace in a scratch
	 * snap and the result returned. Note that the machine could be interrupted having only
	 * partially executed an instruction. Thus, the schedule may specify p-code operations. The
	 * schedule will place the program counter on the instruction (or p-code op) causing the
	 * interruption. Thus, except for breakpoints, attempting to step again will interrupt the
	 * emulator again.
	 * 
	 * @param platform the trace platform containing the initial state
	 * @param from a schedule for the machine's initial state
	 * @param monitor a monitor cancellation
	 * @param scheduler a thread scheduler for the emulator
	 * @return the result of emulation
	 */
	EmulationResult run(TracePlatform platform, TraceSchedule from, TaskMonitor monitor,
			Scheduler scheduler) throws CancelledException;

	/**
	 * Invoke {@link #emulate(Trace, TraceSchedule, TaskMonitor)} in the background
	 * 
	 * <p>
	 * This is the preferred means of performing definite emulation. Because the underlying emulator
	 * may request a <em>blocking</em> read from a target, it is important that
	 * {@link #emulate(TracePlatform, TraceSchedule, TaskMonitor) emulate} is <em>never</em> called
	 * by the Swing thread.
	 * 
	 * @param platform the trace platform containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @return a future which completes with the result of
	 *         {@link #emulate(TracePlatform, TraceSchedule, TaskMonitor) emulate}
	 */
	CompletableFuture<Long> backgroundEmulate(TracePlatform platform, TraceSchedule time);

	/**
	 * Invoke {@link #run(TracePlatform, TraceSchedule, TaskMonitor, Scheduler)} in the background
	 * 
	 * <p>
	 * This is the preferred means of performing indefinite emulation, for the same reasons as
	 * {@link #backgroundEmulate(TracePlatform, TraceSchedule) emulate}.
	 * 
	 * @param platform the trace platform containing the initial state
	 * @param from a schedule for the machine's initial state
	 * @param scheduler a thread scheduler for the emulator
	 * @return a future which completes with the result of
	 *         {@link #run(TracePlatform, TraceSchedule, TaskMonitor, Scheduler) run}.
	 */
	CompletableFuture<EmulationResult> backgroundRun(TracePlatform platform, TraceSchedule from,
			Scheduler scheduler);

	/**
	 * Get the cached emulator for the given trace and time
	 * 
	 * <p>
	 * To guarantee the emulator is present, call {@link #backgroundEmulate(Trace, TraceSchedule)}
	 * first.
	 * <p>
	 * <b>WARNING:</b> This emulator belongs to this service. Stepping it, or otherwise manipulating
	 * it without the service's knowledge can lead to unintended consequences.
	 * <p>
	 * TODO: Should cache by (Platform, Time) instead, but need a way to distinguish platform in the
	 * trace's time table.
	 * 
	 * @param trace the trace containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @return the copied p-code frame
	 */
	DebuggerPcodeMachine<?> getCachedEmulator(Trace trace, TraceSchedule time);

	/**
	 * Get the emulators which are current executing
	 * 
	 * @return the collection
	 */
	Collection<CachedEmulator> getBusyEmulators();

	/**
	 * Add a listener for emulator state changes
	 * 
	 * @param listener the listener
	 */
	void addStateListener(EmulatorStateListener listener);

	/**
	 * Remove a listener for emulator state changes
	 * 
	 * @param listener the listener
	 */
	void removeStateListener(EmulatorStateListener listener);
}
