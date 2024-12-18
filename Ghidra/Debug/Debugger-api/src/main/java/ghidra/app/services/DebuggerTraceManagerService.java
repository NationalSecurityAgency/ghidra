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

import ghidra.async.AsyncReference;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.TriConsumer;

/**
 * The interface for managing open traces and navigating among them and their contents
 */
@ServiceInfo(
	defaultProviderName = "ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin")
public interface DebuggerTraceManagerService {

	/**
	 * The reason coordinates were activated
	 */
	public enum ActivationCause {
		/**
		 * The change was driven by the user
		 * 
		 * <p>
		 * TODO: Distinguish between API and GUI?
		 */
		USER,
		/**
		 * A trace was activated because a target was published or withdrawn
		 */
		TARGET_UPDATED,
		/**
		 * The change was driven by the model activation, possibly indirectly by the user
		 */
		SYNC_MODEL,
		/**
		 * The change was driven by the recorder advancing a snapshot
		 */
		FOLLOW_PRESENT,
		/**
		 * The tool is activating scratch coordinates to display an emulator state change
		 */
		EMU_STATE_EDIT,
		/**
		 * The change was caused by a change to the mapper selection, probably indirectly by the
		 * user
		 */
		MAPPER_CHANGED,
		/**
		 * Some default coordinates were activated
		 * 
		 * <p>
		 * Please don't misunderstand this as the "default cause." Rather, e.g., when the current
		 * trace is closed, and the manager needs to activate new coordinates, it is activating
		 * "default coordinates."
		 */
		ACTIVATE_DEFAULT,
		/**
		 * The tool is restoring its data state
		 */
		RESTORE_STATE,
	}

	/**
	 * An adapter that works nicely with an {@link AsyncReference}
	 * 
	 * <p>
	 * TODO: Seems this is still leaking an implementation detail
	 */
	public interface BooleanChangeAdapter extends TriConsumer<Boolean, Boolean, Void> {
		@Override
		default void accept(Boolean oldVal, Boolean newVal, Void cause) {
			changed(newVal);
		}

		/**
		 * The value has changed
		 * 
		 * @param value the new value
		 */
		void changed(Boolean value);
	}

	/**
	 * Get all the open traces
	 * 
	 * @return all open traces
	 */
	Collection<Trace> getOpenTraces();

	/**
	 * Get the current coordinates
	 * 
	 * <p>
	 * This entails everything except the current address.
	 * 
	 * @return the current coordinates
	 */
	DebuggerCoordinates getCurrent();

	/**
	 * Get the current coordinates for a given trace
	 * 
	 * @param trace the trace
	 * @return the current coordinates for the trace
	 */
	DebuggerCoordinates getCurrentFor(Trace trace);

	/**
	 * Get the active trace
	 * 
	 * @return the active trace, or null
	 */
	Trace getCurrentTrace();

	/**
	 * Get the active platform
	 * 
	 * @return the active platform, or null
	 */
	TracePlatform getCurrentPlatform();

	/**
	 * Get the active view
	 * 
	 * <p>
	 * Every trace has an associated variable-snap view. When the manager navigates to a new point
	 * in time, it is accomplished by changing the snap of this view. This view is suitable for use
	 * in most places where a {@link Program} is ordinarily required.
	 * 
	 * @return the active view, or null
	 */
	TraceProgramView getCurrentView();

	/**
	 * Get the active thread
	 * 
	 * <p>
	 * It is possible to have an active trace, but no active thread.
	 * 
	 * @return the active thread, or null
	 */
	TraceThread getCurrentThread();

	/**
	 * Get the active snap
	 * 
	 * <p>
	 * Note that if emulation was used to materialize the current coordinates, then the current snap
	 * will differ from the view's snap.
	 * 
	 * @return the active snap, or 0
	 */
	long getCurrentSnap();

	/**
	 * Get the active frame
	 * 
	 * @return the active frame, or 0
	 */
	int getCurrentFrame();

	/**
	 * Get the active object
	 * 
	 * @return the active object, or null
	 */
	TraceObject getCurrentObject();

	/**
	 * Open a trace
	 * 
	 * <p>
	 * This does not activate the trace. Use {@link #activateTrace(Trace)} or
	 * {@link #activateThread(TraceThread)} if necessary.
	 * 
	 * @param trace the trace to open
	 */
	void openTrace(Trace trace);

	/**
	 * Open a trace from a domain file
	 * 
	 * @param file the domain file to open
	 * @param version the version (read-only if non-default)
	 * @return the trace
	 * @throws ClassCastException if the domain object contains a non-trace object
	 */
	Trace openTrace(DomainFile file, int version);

	/**
	 * Open traces from a collection of domain files
	 * 
	 * <p>
	 * Iterating the returned trace collection orders each trace by position of its file in the
	 * input file collection.
	 * 
	 * @param files the domain files
	 * @return the traces opened
	 */
	Collection<Trace> openTraces(Collection<DomainFile> files);

	/**
	 * Save the trace to the "New Traces" folder of the project
	 * 
	 * <p>
	 * If a different domain file of the trace's name already exists, an incrementing integer is
	 * appended. Errors are handled in the same fashion as saving a program, so there is little/no
	 * need to invoke {@link CompletableFuture#exceptionally(java.util.function.Function)} on the
	 * returned future. The future is returned as a means of registering follow-up actions.
	 * 
	 * <p>
	 * TODO: Support save-as, prompting to overwrite, etc?
	 * 
	 * @param trace the trace to save
	 * @return a future which completes when the save is finished
	 */
	CompletableFuture<Void> saveTrace(Trace trace);

	/**
	 * Close the given trace
	 * 
	 * @param trace the trace to close
	 */
	void closeTrace(Trace trace);

	/**
	 * Close the given trace without confirmation
	 * 
	 * <p>
	 * Ordinarily, {@link #closeTrace(Trace)} will prompt the user to confirm termination of live
	 * targets associated with traces to be closed. Such prompts can cause issues during automated
	 * tests.
	 * 
	 * @param trace the trace to close
	 */
	void closeTraceNoConfirm(Trace trace);

	/**
	 * Close all traces
	 */
	void closeAllTraces();

	/**
	 * Close all traces except the given one
	 * 
	 * @param keep the trace to keep open
	 */
	void closeOtherTraces(Trace keep);

	/**
	 * Close all traces which are not the destination of a live recording
	 * 
	 * <p>
	 * Operation of this method depends on the model service. If that service is not present, this
	 * method performs no operation at all.
	 */
	void closeDeadTraces();

	/**
	 * Activate the given coordinates with future notification
	 * 
	 * <p>
	 * This operation may be completed asynchronously, esp., if emulation is required to materialize
	 * the coordinates. The returned future is completed when the coordinates are actually
	 * materialized and active. The coordinates are "resolved" as a means of filling in missing
	 * parts. For example, if the thread is not specified, the manager may activate the last-active
	 * thread for the desired trace.
	 * 
	 * @param coordinates the desired coordinates
	 * @param cause the cause of the activation
	 * @return a future which completes when emulation and navigation is complete
	 */
	CompletableFuture<Void> activateAndNotify(DebuggerCoordinates coordinates,
			ActivationCause cause);

	/**
	 * Activate the given coordinates, caused by the user
	 * 
	 * @see #activate(DebuggerCoordinates, ActivationCause)
	 * @param coordinates the desired coordinates
	 */
	default void activate(DebuggerCoordinates coordinates) {
		activate(coordinates, ActivationCause.USER);
	}

	/**
	 * Activate the given coordinates, synchronizing the current target, if possible
	 * 
	 * <p>
	 * If asynchronous notification is needed, use
	 * {@link #activateAndNotify(DebuggerCoordinates, ActivationCause)}.
	 * 
	 * @param coordinates the desired coordinates
	 * @param cause the cause of activation
	 */
	void activate(DebuggerCoordinates coordinates, ActivationCause cause);

	/**
	 * Resolve coordinates for the given trace using the manager's "best judgment"
	 * 
	 * <p>
	 * The manager may use a variety of sources of context including the current trace, the last
	 * coordinates for a trace, the target's last/current activation, the list of live threads, etc.
	 * 
	 * @param trace the trace
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveTrace(Trace trace);

	/**
	 * Activate the given trace
	 * 
	 * @param trace the desired trace
	 */
	default void activateTrace(Trace trace) {
		activate(resolveTrace(trace));
	}

	/**
	 * Resolve coordinates for the given target using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param target the target
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveTarget(Target target);

	/**
	 * Activate the given target
	 * 
	 * @param target the desired target
	 */
	default void activateTarget(Target target) {
		activate(resolveTarget(target));
	}

	/**
	 * Resolve coordinates for the given platform using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param platform the platform
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolvePlatform(TracePlatform platform);

	/**
	 * Activate the given platform
	 * 
	 * @param platform the desired platform
	 */
	default void activatePlatform(TracePlatform platform) {
		activate(resolvePlatform(platform));
	}

	/**
	 * Resolve coordinates for the given thread using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param thread the thread
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveThread(TraceThread thread);

	/**
	 * Activate the given thread
	 * 
	 * @param thread the desired thread
	 */
	default void activateThread(TraceThread thread) {
		activate(resolveThread(thread));
	}

	/**
	 * Resolve coordinates for the given snap using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param snap the snapshot key
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveSnap(long snap);

	/**
	 * Activate the given snapshot key
	 * 
	 * @param snap the desired snapshot key
	 */
	default void activateSnap(long snap) {
		activate(resolveSnap(snap));
	}

	/**
	 * Resolve coordinates for the given time using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param time the time
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveTime(TraceSchedule time);

	/**
	 * Activate the given point in time, possibly invoking emulation
	 * 
	 * @param time the desired schedule
	 */
	default void activateTime(TraceSchedule time) {
		activate(resolveTime(time));
	}

	/**
	 * Resolve coordinates for the given view using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param view the view
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveView(TraceProgramView view);

	/**
	 * Resolve coordinates for the given frame level using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param frameLevel the frame level, 0 being the innermost
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveFrame(int frameLevel);

	/**
	 * Activate the given stack frame
	 * 
	 * @param frameLevel the level of the desired frame, 0 being innermost
	 */
	default void activateFrame(int frameLevel) {
		activate(resolveFrame(frameLevel));
	}

	/**
	 * Resolve coordinates for the given object path using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param path the path
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolvePath(TraceObjectKeyPath path);

	/**
	 * Activate the given canonical object path
	 * 
	 * @param path the desired path
	 */
	default void activatePath(TraceObjectKeyPath path) {
		activate(resolvePath(path));
	}

	/**
	 * Resolve coordinates for the given object using the manager's "best judgment"
	 * 
	 * @see #resolveTrace(Trace)
	 * @param object the object
	 * @return the best coordinates
	 */
	DebuggerCoordinates resolveObject(TraceObject object);

	/**
	 * Activate the given object
	 * 
	 * @param object the desired object
	 */
	default void activateObject(TraceObject object) {
		activate(resolveObject(object));
	}

	/**
	 * Control whether traces should be saved by default
	 * 
	 * @param enabled true to save by default, false otherwise
	 */
	void setSaveTracesByDefault(boolean enabled);

	/**
	 * Check whether traces should by saved by default
	 * 
	 * @return true if saved by default, false otherwise
	 */
	boolean isSaveTracesByDefault();

	/**
	 * Add a listener for changes to save-by-default enablement
	 * 
	 * @param listener the listener to receive change notifications
	 */
	void addSaveTracesByDefaultChangeListener(BooleanChangeAdapter listener);

	/**
	 * Remove a listener for changes to save-by-default enablement
	 * 
	 * @param listener the listener receiving change notifications
	 */
	void removeSaveTracesByDefaultChangeListener(BooleanChangeAdapter listener);

	/**
	 * Control whether live traces are automatically closed upon target termination
	 * 
	 * @param enabled true to automatically close, false to leave open
	 */
	void setAutoCloseOnTerminate(boolean enabled);

	/**
	 * Check whether live traces are automatically closed upon target termination
	 * 
	 * @return true if automatically closed, false if left open
	 */
	boolean isAutoCloseOnTerminate();

	/**
	 * Add a listener for changes to close-on-terminate enablement
	 * 
	 * @param listener the listener to receive change notifications
	 */
	void addAutoCloseOnTerminateChangeListener(BooleanChangeAdapter listener);

	/**
	 * Remove a listener for changes to close-on-terminate enablement
	 * 
	 * @param listener the listener receiving change notifications
	 */
	void removeAutoCloseOnTerminateChangeListener(BooleanChangeAdapter listener);

	/**
	 * If the given coordinates are already materialized, get the snapshot
	 * 
	 * <p>
	 * If the coordinates do not include a schedule, this simply returns the coordinates' snapshot.
	 * Otherwise, it searches for the first snapshot whose schedule is the coordinates' schedule.
	 * 
	 * @param coordinates the coordinates
	 * @return the materialized snapshot key, or null if not materialized.
	 */
	Long findSnapshot(DebuggerCoordinates coordinates);

	/**
	 * Materialize the given coordinates to a snapshot in the same trace
	 * 
	 * <p>
	 * If the given coordinates do not require emulation, then this must complete immediately with
	 * the snapshot key given by the coordinates. If the given schedule is already materialized in
	 * the trace, then this may complete immediately with the previously-materialized snapshot key.
	 * Otherwise, this must invoke emulation, store the result into a chosen snapshot, and complete
	 * with its key.
	 * 
	 * @param coordinates the coordinates to materialize
	 * @return a future that completes with the snapshot key of the materialized coordinates
	 */
	CompletableFuture<Long> materialize(DebuggerCoordinates coordinates);
}
