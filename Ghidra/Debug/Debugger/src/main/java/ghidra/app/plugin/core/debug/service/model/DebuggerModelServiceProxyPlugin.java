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
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.builder.MultiStateActionBuilder;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.DebugProgramAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.DisconnectAllAction;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils;
import ghidra.app.services.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetThread;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@PluginInfo( //
	shortDescription = "Debugger models manager service (proxy to front-end)", //
	description = "Manage debug sessions, connections, and trace recording", //
	category = PluginCategoryNames.DEBUGGER, //
	packageName = DebuggerPluginPackage.NAME, //
	status = PluginStatus.RELEASED, //
	eventsConsumed = { ProgramActivatedPluginEvent.class, //
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

	private static final String KEY_MOST_RECENT_LAUNCHES = "mostRecentLaunches";

	private static final DebuggerProgramLaunchOffer DUMMY_LAUNCH_OFFER =
		new DebuggerProgramLaunchOffer() {
			@Override
			public CompletableFuture<Void> launchProgram(TaskMonitor monitor, boolean prompt) {
				throw new AssertionError("Who clicked me?");
			}

			@Override
			public String getConfigName() {
				return "DUMMY";
			}

			@Override
			public String getMenuParentTitle() {
				return "";
			}

			@Override
			public String getMenuTitle() {
				return "";
			}

			@Override
			public String getQuickTitle() {
				return "";
			}

			@Override
			public String getButtonTitle() {
				return "No quick launcher for the current program";
			}
		};
	private static final ActionState<DebuggerProgramLaunchOffer> DUMMY_LAUNCH_STATE =
		new ActionState<>(DUMMY_LAUNCH_OFFER.getButtonTitle(), DUMMY_LAUNCH_OFFER.getIcon(),
			DUMMY_LAUNCH_OFFER);

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
	@SuppressWarnings("unused") // need strong obj
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

	MultiStateDockingAction<DebuggerProgramLaunchOffer> actionDebugProgram;
	Set<DockingAction> actionDebugProgramMenus = new HashSet<>();
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
		MultiStateActionBuilder<DebuggerProgramLaunchOffer> builderDebugProgram =
			DebugProgramAction.buttonBuilder(this, delegate);
		actionDebugProgram = builderDebugProgram
				.enabledWhen(ctx -> currentProgram != null)
				.onAction(this::debugProgramButtonActivated)
				.onActionStateChanged(this::debugProgramStateActivated)
				.performActionOnButtonClick(true)
				.addState(DUMMY_LAUNCH_STATE)
				.buildAndInstall(tool);
		actionDisconnectAll = DisconnectAllAction.builder(this, delegate)
				.menuPath("Debugger", DisconnectAllAction.NAME)
				.onAction(this::activatedDisconnectAll)
				.buildAndInstall(tool);

		updateActionDebugProgram();
	}

	private void activatedDisconnectAll(ActionContext context) {
		closeAllModels();
	}

	@Override
	public CompletableFuture<DebuggerObjectModel> showConnectDialog(DebuggerModelFactory factory) {
		return delegate.doShowConnectDialog(tool, factory);
	}

	@Override
	public Stream<DebuggerProgramLaunchOffer> getProgramLaunchOffers(Program program) {
		return orderOffers(delegate.getProgramLaunchOffers(program), program);
	}

	protected List<String> readMostRecentLaunches(Program program) {
		StringPropertyMap prop = program.getProgramUserData()
				.getStringProperty(getName(), KEY_MOST_RECENT_LAUNCHES, false);
		if (prop == null) {
			return List.of();
		}
		Address min = program.getAddressFactory().getDefaultAddressSpace().getMinAddress();
		String str = prop.getString(min);
		if (str == null) {
			return List.of();
		}
		return List.of(str.split(";"));
	}

	protected void writeMostRecentLaunches(Program program, List<String> mrl) {
		ProgramUserData userData = program.getProgramUserData();
		try (UndoableTransaction tid = UndoableTransaction.start(userData)) {
			StringPropertyMap prop = userData
					.getStringProperty(getName(), KEY_MOST_RECENT_LAUNCHES, true);
			Address min = program.getAddressFactory().getDefaultAddressSpace().getMinAddress();
			prop.add(min, mrl.stream().collect(Collectors.joining(";")));
		}
	}

	static class OfferComparator implements Comparator<DebuggerProgramLaunchOffer> {
		Map<String, Integer> fastIndex = new HashMap<>();

		public OfferComparator(List<String> mostRecentNames) {
			int i = 0;
			for (String name : mostRecentNames) {
				fastIndex.put(name, i++);
			}
		}

		@Override
		public int compare(DebuggerProgramLaunchOffer o1, DebuggerProgramLaunchOffer o2) {
			int i1 = fastIndex.getOrDefault(o1, -1);
			int i2 = fastIndex.getOrDefault(o2, -1);
			int result = i1 - i2; // reversed, yes. Most recent is last in list 
			if (result != 0) {
				return result;
			}
			return o1.defaultPriority() - o2.defaultPriority(); // Greater is higher priority
		}
	}

	protected Stream<DebuggerProgramLaunchOffer> orderOffers(
			Stream<DebuggerProgramLaunchOffer> offers, Program program) {
		List<String> mrl = readMostRecentLaunches(program);
		return offers.sorted(Comparator.comparingInt(o -> -mrl.indexOf(o.getConfigName())));
	}

	private void debugProgram(DebuggerProgramLaunchOffer offer, Program program, boolean prompt) {
		BackgroundUtils.async(tool, program, offer.getButtonTitle(), true, true, true, (p, m) -> {
			List<String> mrl = new ArrayList<>(readMostRecentLaunches(program));
			mrl.remove(offer.getConfigName());
			mrl.add(offer.getConfigName());
			writeMostRecentLaunches(program, mrl);
			CompletableFuture.runAsync(() -> {
				updateActionDebugProgram();
			}, AsyncUtils.SWING_EXECUTOR).exceptionally(ex -> {
				Msg.error(this, "Trouble writing recent launches to program user data");
				return null;
			});
			return offer.launchProgram(m, prompt).exceptionally(ex -> {
				Throwable t = AsyncUtils.unwrapThrowable(ex);
				if (t instanceof CancellationException || t instanceof CancelledException) {
					return null;
				}
				return ExceptionUtils.rethrow(ex);
			}).whenCompleteAsync((v, e) -> {
				updateActionDebugProgram();
			}, AsyncUtils.SWING_EXECUTOR);
		});
	}

	private void debugProgramButtonActivated(ActionContext ctx) {
		DebuggerProgramLaunchOffer offer = actionDebugProgram.getCurrentUserData();
		Program program = currentProgram;
		if (offer == null || program == null) {
			return;
		}
		debugProgram(offer, program, false);
	}

	private void debugProgramStateActivated(ActionState<DebuggerProgramLaunchOffer> offer,
			EventTrigger trigger) {
		if (trigger == EventTrigger.GUI_ACTION) {
			debugProgramButtonActivated(null);
		}
	}

	private void debugProgramMenuActivated(DebuggerProgramLaunchOffer offer) {
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		debugProgram(offer, program, true);
	}

	private void updateActionDebugProgram() {
		if (actionDebugProgram == null) {
			return;
		}
		Program program = currentProgram;
		List<DebuggerProgramLaunchOffer> offers = program == null ? List.of()
				: getProgramLaunchOffers(program).collect(Collectors.toList());
		List<ActionState<DebuggerProgramLaunchOffer>> states = offers.stream()
				.map(o -> new ActionState<DebuggerProgramLaunchOffer>(o.getButtonTitle(),
					o.getIcon(), o))
				.collect(Collectors.toList());
		if (!states.isEmpty()) {
			actionDebugProgram.setActionStates(states);
			actionDebugProgram.setEnabled(true);
			actionDebugProgram.setCurrentActionState(states.get(0));
		}
		else {
			actionDebugProgram.setActionStates(List.of(DUMMY_LAUNCH_STATE));
			actionDebugProgram.setEnabled(false);
			actionDebugProgram.setCurrentActionState(DUMMY_LAUNCH_STATE);
		}

		for (Iterator<DockingAction> it = actionDebugProgramMenus.iterator(); it.hasNext();) {
			DockingAction action = it.next();
			it.remove();
			tool.removeAction(action);
		}
		for (DebuggerProgramLaunchOffer offer : offers) {
			actionDebugProgramMenus.add(DebugProgramAction.menuBuilder(offer, this, delegate)
					.onAction(ctx -> debugProgramMenuActivated(offer))
					.buildAndInstall(tool));
		}
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
	public TraceRecorder recordTarget(TargetObject target, DebuggerTargetTraceMapper mapper)
			throws IOException {
		return delegate.recordTarget(target, mapper);
	}

	@Override
	public TraceRecorder recordTargetBestOffer(TargetObject target) {
		return delegate.recordTargetBestOffer(target);
	}

	@Override
	public TraceRecorder doRecordTargetPromptOffers(PluginTool t, TargetObject target) {
		return delegate.doRecordTargetPromptOffers(t, target);
	}

	@Override
	public TraceRecorder recordTargetPromptOffers(TargetObject target) {
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
	public TraceRecorder getRecorderForSuccessor(TargetObject obj) {
		return delegate.getRecorderForSuccessor(obj);
	}

	@Override
	public TraceRecorder getRecorder(Trace trace) {
		return delegate.getRecorder(trace);
	}

	@Override
	public TargetThread getTargetThread(TraceThread thread) {
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
	public TraceThread getTraceThread(TargetThread thread) {
		return delegate.getTraceThread(thread);
	}

	@Override
	public TraceThread getTraceThread(TargetObject target, TargetThread thread) {
		return delegate.getTraceThread(target, thread);
	}

	@Override
	public TargetObject getTargetFocus(TargetObject target) {
		return delegate.getTargetFocus(target);
	}
}
