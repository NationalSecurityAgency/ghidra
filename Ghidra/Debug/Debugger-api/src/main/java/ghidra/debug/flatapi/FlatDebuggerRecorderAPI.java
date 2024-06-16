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

import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.util.PathUtils;
import ghidra.debug.api.model.DebuggerProgramLaunchOffer;
import ghidra.debug.api.model.DebuggerProgramLaunchOffer.*;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

@Deprecated
public interface FlatDebuggerRecorderAPI extends FlatDebuggerAPI {

	/**
	 * Get the model (legacy target) service
	 * 
	 * @return the service
	 */
	default DebuggerModelService getModelService() {
		return requireService(DebuggerModelService.class);
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
	 * @param trace the trace
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

	@Override
	default void waitForBreak(Trace trace, long timeout, TimeUnit unit) throws TimeoutException {
		TargetObject target = getTarget(trace);
		if (target == null || !target.isValid()) {
			return;
		}
		waitForBreak(target, timeout, unit);
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
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This override includes flushing the recorder's event and transaction queues.
	 */
	@Override
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
}
