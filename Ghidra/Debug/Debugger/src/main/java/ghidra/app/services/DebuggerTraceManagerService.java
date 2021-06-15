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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.util.TriConsumer;

@ServiceInfo(defaultProvider = DebuggerTraceManagerServicePlugin.class)
public interface DebuggerTraceManagerService {
	public interface BooleanChangeAdapter extends TriConsumer<Boolean, Boolean, Void> {
		@Override
		default void accept(Boolean oldVal, Boolean newVal, Void cause) {
			changed(newVal);
		}

		void changed(Boolean value);
	}

	Collection<Trace> getOpenTraces();

	DebuggerCoordinates getCurrent();

	Trace getCurrentTrace();

	TraceProgramView getCurrentView();

	TraceThread getCurrentThread();

	TraceThread getCurrentThreadFor(Trace trace);

	long getCurrentSnap();

	int getCurrentFrame();

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

	void closeTrace(Trace trace);

	void closeAllTraces();

	void closeOtherTraces(Trace keep);

	/**
	 * Close all traces which are not the destination of a live recording
	 * 
	 * <p>
	 * Operation of this method depends on the model service. If that service is not present, this
	 * method performs no operation at all.
	 */
	void closeDeadTraces();

	void activate(DebuggerCoordinates coordinates);

	void activateTrace(Trace trace);

	void activateThread(TraceThread thread);

	void activateSnap(long snap);

	void activateTime(TraceSchedule time);

	void activateFrame(int frameLevel);

	void setAutoActivatePresent(boolean enabled);

	boolean isAutoActivatePresent();

	void addAutoActivatePresentChangeListener(BooleanChangeAdapter listener);

	void removeAutoActivatePresentChangeListener(BooleanChangeAdapter listener);

	/**
	 * Control whether trace activation is synchronized with debugger focus/select
	 * 
	 * @param enabled true to synchronize, false otherwise
	 */
	void setSynchronizeFocus(boolean enabled);

	/**
	 * Check whether trace activation is synchronized with debugger focus/select
	 * 
	 * @return true if synchronized, false otherwise
	 */
	boolean isSynchronizeFocus();

	void addSynchronizeFocusChangeListener(BooleanChangeAdapter listener);

	void removeSynchronizeFocusChangeListener(BooleanChangeAdapter listener);

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

	void addSaveTracesByDefaultChangeListener(BooleanChangeAdapter listener);

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

	void addAutoCloseOnTerminateChangeListener(BooleanChangeAdapter listener);

	void removeAutoCloseOnTerminateChangeListener(BooleanChangeAdapter listener);

	/**
	 * Fill in an incomplete coordinate specification, using the manager's "best judgement"
	 * 
	 * @param coords the possibly-incomplete coordinates
	 * @return the complete resolved coordinates
	 */
	DebuggerCoordinates resolveCoordinates(DebuggerCoordinates coords);
}
