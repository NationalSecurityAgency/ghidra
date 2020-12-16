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
package ghidra.app.plugin.core.debug.service.model;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.DebugProgramAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.DisconnectAllAction;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils;
import ghidra.app.services.*;
import ghidra.async.SwingExecutorService;
import ghidra.dbg.*;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.task.TaskMonitor;

@PluginInfo( //
		shortDescription = "Debugger models manager service (proxy to front-end)", //
		description = "Manage debug sessions, connections, and trace recording", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		eventsConsumed = {
			ProgramActivatedPluginEvent.class, //
			ProgramClosedPluginEvent.class, //
		}, //
		servicesRequired = { //
			DebuggerTraceManagerService.class, //
		}, //
		servicesProvided = { //
			DebuggerModelService.class, //
		} //
)
public class DebuggerModelServiceProxyPlugin extends Plugin
		implements DebuggerModelServiceInternal {

	protected static DebuggerModelServicePlugin getOrCreateFrontEndDelegate() {
		FrontEndTool frontEnd = AppInfo.getFrontEndTool();
		for (Plugin plugin : frontEnd.getManagedPlugins()) {
			if (plugin instanceof DebuggerModelServicePlugin) {
				return (DebuggerModelServicePlugin) plugin;
			}
		}
		try {
			DebuggerModelServicePlugin plugin =
				PluginUtils.instantiatePlugin(DebuggerModelServicePlugin.class, frontEnd);
			frontEnd.addPlugin(plugin);
			return plugin;
		}
		catch (PluginException e) {
			throw new AssertionError(e);
		}
	}

	protected class ProxiedFactoryChangeListener
			implements CollectionChangeListener<DebuggerModelFactory> {
		@Override
		public void elementAdded(DebuggerModelFactory element) {
			factoryListeners.fire.elementAdded(element);
		}

		@Override
		public void elementRemoved(DebuggerModelFactory element) {
			factoryListeners.fire.elementRemoved(element);
		}

		@Override
		public void elementModified(DebuggerModelFactory element) {
			factoryListeners.fire.elementModified(element);
		}
	}

	protected class ProxiedModelChangeListener
			implements CollectionChangeListener<DebuggerObjectModel> {
		@Override
		public void elementAdded(DebuggerObjectModel element) {
			modelListeners.fire.elementAdded(element);
		}

		@Override
		public void elementRemoved(DebuggerObjectModel element) {
			if (currentModel == element) {
				activateModel(null);
			}
			modelListeners.fire.elementRemoved(element);
		}

		@Override
		public void elementModified(DebuggerObjectModel element) {
			modelListeners.fire.elementModified(element);
		}
	}

	protected class ProxiedRecorderChangeListener
			implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder element) {
			recorderListeners.fire.elementAdded(element);
		}

		@Override
		public void elementRemoved(TraceRecorder element) {
			recorderListeners.fire.elementRemoved(element);
		}

		@Override
		public void elementModified(TraceRecorder element) {
			recorderListeners.fire.elementModified(element);
		}
	}

	protected DebuggerModelServicePlugin delegate;

	/*@AutoServiceConsumed
	private ProgramManager programManager;
	@SuppressWarnings("unused") // need strong ref
	private AutoService.Wiring autoServiceWiring;*/

	// This is not delegated. Each tool can have its own active model.
	protected DebuggerObjectModel currentModel;
	// Focus within the model, however, is controlled by the model, so it is global
	protected Program currentProgram;
	protected File currentProgramPath;

	protected final ProxiedFactoryChangeListener factoryChangeListener =
		new ProxiedFactoryChangeListener();
	protected final ProxiedModelChangeListener modelChangeListener =
		new ProxiedModelChangeListener();
	protected final ProxiedRecorderChangeListener recorderChangeListener =
		new ProxiedRecorderChangeListener();

	DockingAction actionDebugProgram;
	DockingAction actionDisconnectAll;

	protected final ListenerSet<CollectionChangeListener<DebuggerModelFactory>> factoryListeners =
		new ListenerSet<>(CollectionChangeListener.of(DebuggerModelFactory.class));
	protected final ListenerSet<CollectionChangeListener<DebuggerObjectModel>> modelListeners =
		new ListenerSet<>(CollectionChangeListener.of(DebuggerObjectModel.class));
	protected final ListenerSet<CollectionChangeListener<TraceRecorder>> recorderListeners =
		new ListenerSet<>(CollectionChangeListener.of(TraceRecorder.class));

	public DebuggerModelServiceProxyPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		delegate = getOrCreateFrontEndDelegate();
		delegate.addProxy(this);
		delegate.addFactoriesChangedListener(factoryChangeListener);
		delegate.addModelsChangedListener(modelChangeListener);
		delegate.addTraceRecordersChangedListener(recorderChangeListener);

		createActions();
	}

	protected void createActions() {
		// Note, I have to give an enabledWhen, otherwise any context change re-enables it
		actionDebugProgram = DebugProgramAction.builder(this, delegate)
				.enabledWhen(ctx -> currentProgramPath != null)
				.onAction(this::debugProgramActivated)
				.buildAndInstall(tool);
		actionDisconnectAll = DisconnectAllAction.builder(this, delegate)
				.menuPath("Debugger", DisconnectAllAction.NAME)
				.onAction(this::activatedDisconnectAll)
				.buildAndInstall(tool);

		updateActionDebugProgram();
	}

	private void debugProgramActivated(ActionContext ctx) {
		if (currentProgramPath == null) {
			return;
		}
		/**
		 * Note the background task must have an object for a "transaction", even though this
		 * particular task doesn't actually touch the program. Annoying.
		 */
		BackgroundUtils.async(tool, currentProgram, actionDebugProgram.getDescription(), true, true,
			true, this::debugProgram);
	}

	private void activatedDisconnectAll(ActionContext context) {
		closeAllModels();
	}

	private CompletableFuture<Void> debugProgram(Program __, TaskMonitor monitor) {
		monitor.initialize(3);
		monitor.setMessage("Starting local session");
		return startLocalSession().thenCompose(model -> {
			CompletableFuture<Void> swing = CompletableFuture.runAsync(() -> {
				// Needed to auto-record via objects provider
				activateModel(model);
			}, SwingExecutorService.INSTANCE);
			return swing.thenCompose(___ -> model.fetchModelRoot());
		}).thenCompose(root -> {
			monitor.incrementProgress(1);
			monitor.setMessage("Finding launcher");
			CompletableFuture<? extends TargetLauncher<?>> futureLauncher =
				DebugModelConventions.findSuitable(TargetLauncher.tclass, root);
			return futureLauncher;
		}).thenCompose(launcher -> {
			monitor.incrementProgress(1);
			monitor.setMessage("Launching " + currentProgramPath);
			// TODO: Pluggable ways to populate this
			// TODO: Maybe still prompt the user?
			// TODO: Launch configurations, like Eclipse?
			// TODO: Maybe just let the pluggable thing invoke launch itself
			return launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, currentProgramPath.toString()));
		});
	}

	private void updateActionDebugProgram() {
		if (actionDebugProgram == null) {
			return;
		}
		actionDebugProgram.setEnabled(currentProgramPath != null);
		String desc = currentProgramPath == null ? DebugProgramAction.DESCRIPTION_PREFIX.trim()
				: DebugProgramAction.DESCRIPTION_PREFIX + currentProgramPath;
		actionDebugProgram.setDescription(desc);
		actionDebugProgram.getMenuBarData().setMenuItemName(desc);
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (delegate != null) {
			delegate.removeProxy(this);
			delegate.removeFactoriesChangedListener(factoryChangeListener);
			delegate.removeModelsChangedListener(modelChangeListener);
			delegate.removeTraceRecordersChangedListener(recorderChangeListener);
		}
		currentModel = null;
	}

	private File getProgramPath(Program program) {
		if (program == null) {
			return null;
		}
		String path = program.getExecutablePath();
		if (path == null) {
			return null;
		}
		File file = new File(path);
		try {
			if (!file.canExecute()) {
				return null;
			}
			return file.getCanonicalFile();
		}
		catch (SecurityException | IOException e) {
			Msg.error(this, "Cannot examine file " + path, e);
			return null;
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent evt = (ProgramActivatedPluginEvent) event;
			currentProgram = evt.getActiveProgram();
			currentProgramPath = getProgramPath(currentProgram);

			updateActionDebugProgram();
		}
		if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent evt = (ProgramClosedPluginEvent) event;
			if (currentProgram == evt.getProgram()) {
				currentProgram = null;
				currentProgramPath = null;

				updateActionDebugProgram();
			}
		}
	}

	@Override
	public void refreshFactoryInstances() {
		delegate.refreshFactoryInstances();
	}

	@Override
	public void setModelFactories(Collection<DebuggerModelFactory> factories) {
		delegate.setModelFactories(factories);
	}

	@Override
	public Set<DebuggerModelFactory> getModelFactories() {
		return delegate.getModelFactories();
	}

	@Override
	public Set<DebuggerObjectModel> getModels() {
		return delegate.getModels();
	}

	@Override
	public CompletableFuture<Void> closeAllModels() {
		return delegate.closeAllModels();
	}

	@Override
	public Collection<TraceRecorder> getTraceRecorders() {
		return delegate.getTraceRecorders();
	}

	@Override
	public boolean addModel(DebuggerObjectModel model) {
		return delegate.addModel(model);
	}

	@Override
	public boolean removeModel(DebuggerObjectModel model) {
		return delegate.removeModel(model);
	}

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> startLocalSession() {
		return delegate.startLocalSession();
	}

	@Override
	public TraceRecorder recordTarget(TargetObject target, DebuggerTargetTraceMapper mapper)
			throws IOException {
		return delegate.recordTarget(target, mapper);
	}

	@Override
	public CompletableFuture<TraceRecorder> recordTargetBestOffer(TargetObject target) {
		return delegate.recordTargetBestOffer(target);
	}

	@Override
	public CompletableFuture<TraceRecorder> doRecordTargetPromptOffers(PluginTool t,
			TargetObject target) {
		return delegate.doRecordTargetPromptOffers(t, target);
	}

	@Override
	public CompletableFuture<TraceRecorder> recordTargetPromptOffers(TargetObject target) {
		return doRecordTargetPromptOffers(tool, target);
	}

	@Override
	public synchronized boolean doActivateModel(DebuggerObjectModel model) {
		if (model == currentModel) {
			return false;
		}
		currentModel = model;
		return true;
	}

	@Override
	public synchronized DebuggerObjectModel getCurrentModel() {
		return currentModel;
	}

	@Override
	public void addFactoriesChangedListener(
			CollectionChangeListener<DebuggerModelFactory> listener) {
		factoryListeners.add(listener);
	}

	@Override
	public void removeFactoriesChangedListener(
			CollectionChangeListener<DebuggerModelFactory> listener) {
		factoryListeners.remove(listener);
	}

	@Override
	public void addModelsChangedListener(CollectionChangeListener<DebuggerObjectModel> listener) {
		modelListeners.add(listener);
	}

	@Override
	public void removeModelsChangedListener(
			CollectionChangeListener<DebuggerObjectModel> listener) {
		modelListeners.remove(listener);
	}

	@Override
	public void addTraceRecordersChangedListener(CollectionChangeListener<TraceRecorder> listener) {
		recorderListeners.add(listener);
	}

	@Override
	public void removeTraceRecordersChangedListener(
			CollectionChangeListener<TraceRecorder> listener) {
		recorderListeners.remove(listener);
	}

	@Override
	public TraceRecorder recordTargetAndActivateTrace(TargetObject target,
			DebuggerTargetTraceMapper mapper, DebuggerTraceManagerService traceManager)
			throws IOException {
		return delegate.recordTargetAndActivateTrace(target, mapper, traceManager);
	}

	@Override
	public TraceRecorder recordTargetAndActivateTrace(TargetObject target,
			DebuggerTargetTraceMapper mapper) throws IOException {
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		return delegate.recordTargetAndActivateTrace(target, mapper, traceManager);
	}

	@Override
	public TraceRecorder getRecorder(TargetObject target) {
		return delegate.getRecorder(target);
	}

	@Override
	public TraceRecorder getRecorderForSuccessor(TargetObjectRef ref) {
		return delegate.getRecorderForSuccessor(ref);
	}

	@Override
	public TraceRecorder getRecorder(Trace trace) {
		return delegate.getRecorder(trace);
	}

	@Override
	public TargetThread<?> getTargetThread(TraceThread thread) {
		return delegate.getTargetThread(thread);
	}

	@Override
	public TargetObject getTarget(Trace trace) {
		return delegate.getTarget(trace);
	}

	@Override
	public Trace getTrace(TargetObject target) {
		return delegate.getTrace(target);
	}

	@Override
	public TraceThread getTraceThread(TargetThread<?> thread) {
		return delegate.getTraceThread(thread);
	}

	@Override
	public TraceThread getTraceThread(TargetObject target, TargetThread<?> thread) {
		return delegate.getTraceThread(target, thread);
	}

	@Override
	public TargetObjectRef getTargetFocus(TargetObject target) {
		return delegate.getTargetFocus(target);
	}
}
