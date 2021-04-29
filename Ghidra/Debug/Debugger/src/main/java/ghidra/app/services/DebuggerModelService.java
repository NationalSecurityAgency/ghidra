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

import java.io.IOException;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.datastruct.CollectionChangeListener;

@ServiceInfo(
	defaultProvider = DebuggerModelServiceProxyPlugin.class,
	description = "Service for managing debug sessions and connections")
public interface DebuggerModelService {
	/**
	 * Get the set of model factories found on the classpath
	 * 
	 * @return the set of factories
	 */
	Set<DebuggerModelFactory> getModelFactories();

	/**
	 * Get the set of models registered with this service
	 * 
	 * @return the set of models
	 */
	Set<DebuggerObjectModel> getModels();

	/**
	 * Disconnect or close all debugging models (connections)
	 * 
	 * @return a future which completes when all models are closed
	 */
	CompletableFuture<Void> closeAllModels();

	/**
	 * Get the set of active recorders
	 *
	 * <p>
	 * A recorder is active as long as its target (usually a process) is valid. It becomes inactive
	 * when the target becomes invalid, or when the user stops the recording.
	 * 
	 * @return the set of recorders
	 */
	Collection<TraceRecorder> getTraceRecorders();

	/**
	 * Register a model with this service
	 * 
	 * <p>
	 * In general, the tool will only display models registered here
	 * 
	 * @param model the model to register
	 * @return true if the model was not already registered
	 */
	boolean addModel(DebuggerObjectModel model);

	/**
	 * Un-register a model
	 * 
	 * @param model the model to un-register
	 * @return true if the model was successfully un-registered, false if the model had never been
	 *         registered or was already un-registered.
	 */
	boolean removeModel(DebuggerObjectModel model);

	/**
	 * Start a new trace on the given target
	 * 
	 * <p>
	 * Following conventions, the target must be a container, usually a process. Ideally, the model
	 * will present the process as having memory, modules, and threads; and the model will present
	 * each thread as having registers, or a stack with frame 0 presenting the registers.
	 * 
	 * <p>
	 * Any given container can be traced by at most one recorder.
	 * 
	 * <p>
	 * TODO: If mappers remain bound to a prospective target, then remove target from the parameters
	 * here.
	 * 
	 * @param target a target to record
	 * @param mapper a mapper between target and trace objects
	 * @return the destination trace
	 * @throws IOException if a trace cannot be created
	 * @see DebuggerMappingOpinion#getOffers(TargetObject)
	 */
	TraceRecorder recordTarget(TargetObject target, DebuggerTargetTraceMapper mapper)
			throws IOException;

	/**
	 * Query mapping opinions and record the given target using the "best" offer
	 * 
	 * <p>
	 * If exactly one offer is given, this simply uses it. If multiple are given, this automatically
	 * chooses the "best" one without prompting the user. If none are given, this fails.
	 * 
	 * @see DebuggerMappingOpinion#queryOpinions(TargetObject)
	 * @param target the target to record.
	 * @return a future which completes with the recorder, or completes exceptionally
	 */
	TraceRecorder recordTargetBestOffer(TargetObject target);

	/**
	 * Query mapping opinions, prompt the user, and record the given target
	 * 
	 * <p>
	 * Even if exactly one offer is given, the user is prompted to provide information about the new
	 * recording, and to give the user an opportunity to cancel. If none are given, the prompt says
	 * as much. If the user cancels, the returned future completes with {@code null}.
	 * 
	 * <p>
	 * TODO: Should the prompt allow the user to force an opinion which gave no offers?
	 * 
	 * @see DebuggerMappingOpinion#queryOpinions(TargetObject)
	 * @param target the target to record.
	 * @return a future which completes with the recorder, or completes exceptionally
	 */
	TraceRecorder recordTargetPromptOffers(TargetObject target);

	/**
	 * Start and open a new trace on the given target
	 *
	 * <p>
	 * Starts a new trace, and opens it in the tool
	 * 
	 * @see #recordTarget(TargetObject)
	 */
	TraceRecorder recordTargetAndActivateTrace(TargetObject target,
			DebuggerTargetTraceMapper mapper) throws IOException;

	/**
	 * Get the recorder which is tracing the given target
	 * 
	 * @param target an object being recorded, usually a process
	 * @return the recorder, or null
	 */
	TraceRecorder getRecorder(TargetObject target);

	/**
	 * Get the recorder which is recording the nearest ancestor for the given object
	 * 
	 * @param obj the object
	 * @return the recorder, or null
	 */
	TraceRecorder getRecorderForSuccessor(TargetObject obj);

	/**
	 * Get the recorder whose destination is the given trace
	 * 
	 * @param trace the destination trace
	 * @return the recorder, or null
	 */
	TraceRecorder getRecorder(Trace trace);

	/**
	 * Get the object (usually a process) associated with the given destination trace
	 *
	 * <p>
	 * A recorder uses conventions to discover the "process" in the model, given a target object.
	 * 
	 * <p>
	 * TODO: Conventions for targets other than processes are not yet specified.
	 * 
	 * @param trace the destination trace
	 * @return the target object
	 */
	TargetObject getTarget(Trace trace);

	/**
	 * Get the destination trace for a given source target
	 * 
	 * @param target the source target, usually a process
	 * @return the destination trace
	 */
	Trace getTrace(TargetObject target);

	/**
	 * Get the object associated with the given destination trace thread
	 * 
	 * <p>
	 * A recorder uses conventions to discover "threads" for a given target object, usually a
	 * process. Those threads are then assigned to corresponding destination trace threads. Assuming
	 * the given trace thread is the destination of an active recorder, this method finds the
	 * corresponding model "thread."
	 * 
	 * <p>
	 * TODO: Conventions for targets other than processes (containing threads) are not yet
	 * specified.
	 * 
	 * @param thread the destination trace thread
	 * @return the source model "thread"
	 */
	TargetThread getTargetThread(TraceThread thread);

	/**
	 * Get the destination trace thread, if applicable, for a given source thread
	 * 
	 * <p>
	 * Consider {@link #getTraceThread(TargetObject, TargetExecutionStateful)} if the caller already
	 * has a handle to the thread's container.
	 * 
	 * @param thread the source model "thread"
	 * @return the destination trace thread
	 */
	TraceThread getTraceThread(TargetThread thread);

	/**
	 * Get the destination trace thread, if applicable, for a given source thread
	 * 
	 * <p>
	 * This method is slightly faster than {@link #getTraceThread(TargetExecutionStateful)}, since
	 * it doesn't have to search for the applicable recorder. However, if the wrong container is
	 * given, this method will fail to find the given thread.
	 * 
	 * @param target the source target, usually a process
	 * @param thread the source model thread
	 * @return the destination trace thread
	 */
	TraceThread getTraceThread(TargetObject target, TargetThread thread);

	/**
	 * Signal to plugins that the user's focus has changed to another model
	 * 
	 * @param model the new model to focus
	 */
	void activateModel(DebuggerObjectModel model);

	/**
	 * Get the active model
	 * 
	 * @return the model
	 */
	DebuggerObjectModel getCurrentModel();

	/**
	 * Get the last focused object related to the given target
	 * 
	 * <p>
	 * Assuming the target object is being actively traced, find the last focused object among those
	 * being traced by the same recorder. Essentially, given that the target likely belongs to a
	 * process, find the object within that process that last had focus. This is primarily used
	 * wh@Override en switching focus between traces. Since the user has not explicitly selected a
	 * model object, the UI should choose the one which had focus when the newly-activated trace was
	 * last active.
	 * 
	 * @param target a source model object being actively traced
	 * @return the last focused object being traced by the same recorder
	 */
	TargetObject getTargetFocus(TargetObject target);

	/**
	 * Listen for changes in available model factories
	 * 
	 * <p>
	 * The caller must keep a strong reference to the listener, or it will be automatically removed.
	 * 
	 * @param listener the listener
	 */
	void addFactoriesChangedListener(CollectionChangeListener<DebuggerModelFactory> listener);

	/**
	 * Remove a listener for changes in available model factories
	 * 
	 * @param listener the listener
	 */
	void removeFactoriesChangedListener(CollectionChangeListener<DebuggerModelFactory> listener);

	/**
	 * Listen for changes in registered models
	 * 
	 * <p>
	 * The caller must beep a strong reference to the listener, or it will be automatically removed.
	 * 
	 * <p>
	 * TODO: Probably replace this with a {@link PluginEvent}
	 * 
	 * @param listener the listener
	 */
	void addModelsChangedListener(CollectionChangeListener<DebuggerObjectModel> listener);

	/**
	 * Remove a listener for changes in registered models
	 * 
	 * <p>
	 * TODO: Probably replace this with a {@link PluginEvent}
	 * 
	 * @param listener the listener
	 */
	void removeModelsChangedListener(CollectionChangeListener<DebuggerObjectModel> listener);

	/**
	 * Listen for changes in active trace recorders
	 * 
	 * <p>
	 * The caller must beep a strong reference to the listener, or it will be automatically removed.
	 * 
	 * <p>
	 * TODO: Probably replace this with a {@link PluginEvent}
	 * 
	 * @param listener the listener
	 */
	void addTraceRecordersChangedListener(CollectionChangeListener<TraceRecorder> listener);

	/**
	 * Remove a listener for changes in active trace recorders
	 * 
	 * <p>
	 * TODO: Probably replace this with a {@link PluginEvent}
	 * 
	 * @param listener the listener
	 */
	void removeTraceRecordersChangedListener(CollectionChangeListener<TraceRecorder> listener);

	/**
	 * Collect all offers for launching the given program
	 * 
	 * @param program the program to launch
	 * @return the offers
	 */
	Stream<DebuggerProgramLaunchOffer> getProgramLaunchOffers(Program program);

	/**
	 * Prompt the user to create a new connection
	 * 
	 * @return a future which completes with the new connection, possibly cancelled
	 */
	default CompletableFuture<DebuggerObjectModel> showConnectDialog() {
		return showConnectDialog(null);
	}

	/**
	 * Prompt the user to create a new connection, optionally fixing the factory
	 * 
	 * @param factory the required factory, or null for user selection
	 * @return a future which completes with the new connection, possible cancelled
	 */
	CompletableFuture<DebuggerObjectModel> showConnectDialog(DebuggerModelFactory factory);
}
