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

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.showError;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.CharBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.jdom.Element;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.DisconnectAllAction;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOpinion;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.async.AsyncFence;
import ghidra.dbg.*;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.debug.api.action.ActionSource;
import ghidra.debug.api.model.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.lifecycle.Internal;
import ghidra.program.model.listing.Program;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.TimedMsg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.datastruct.ListenerSet;

@PluginInfo(
	shortDescription = "Debugger models manager service",
	description = "Manage debug sessions, connections, and trace recording",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.HIDDEN,
	servicesRequired = {},
	servicesProvided = {
		DebuggerModelService.class
	})
public class DebuggerModelServicePlugin extends Plugin
		implements DebuggerModelServiceInternal, ApplicationLevelOnlyPlugin {

	private static final String PREFIX_FACTORY = "Factory_";

	// Since used for naming, no ':' allowed.
	public static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy.MM.dd-HH.mm.ss-z");

	protected class ForRemovalAndFocusListener extends AnnotatedDebuggerAttributeListener {
		public ForRemovalAndFocusListener() {
			super(MethodHandles.lookup());
		}

		@Override
		public void invalidated(TargetObject object, TargetObject branch, String reason) {
			if (!object.isRoot()) {
				return;
			}
			DebuggerObjectModel model = object.getModel();
			synchronized (models) {
				models.remove(model);
			}
			model.removeModelListener(this);
			modelListeners.invoke().elementRemoved(model);
			if (currentModel == model) {
				activateModel(null);
			}
		}

		@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
		public void focusChanged(TargetObject object, TargetObject focused) {
			// I don't think I care which scope
			fireFocusEvent(focused);
			List<DebuggerModelServiceProxyPlugin> copy;
			synchronized (proxies) {
				copy = List.copyOf(proxies);
			}
			for (DebuggerModelServiceProxyPlugin proxy : copy) {
				proxy.fireFocusEvent(focused);
			}
		}
	}

	protected class ListenerOnRecorders implements TraceRecorderListener {
		@Override
		public void snapAdvanced(TraceRecorder recorder, long snap) {
			TimedMsg.debug(this, "Got snapAdvanced callback");
			fireSnapEvent(recorder, snap);
			List<DebuggerModelServiceProxyPlugin> copy;
			synchronized (proxies) {
				copy = List.copyOf(proxies);
			}
			for (DebuggerModelServiceProxyPlugin proxy : copy) {
				TimedMsg.debug(this, "Firing SnapEvent on " + proxy);
				proxy.fireSnapEvent(recorder, snap);
			}
		}

		@Override
		public void recordingStopped(TraceRecorder recorder) {
			removeRecorder(recorder);
		}
	}

	protected class ChangeListenerForFactoryInstances implements ChangeListener {
		@Override
		public void stateChanged(ChangeEvent e) {
			refreshFactoryInstances();
		}
	}

	protected final Set<DebuggerModelServiceProxyPlugin> proxies = new HashSet<>();

	protected final Set<DebuggerModelFactory> factories = new HashSet<>();
	// Keep strong references to my listeners, or they'll get torched
	//protected final Map<DebuggerObjectModel, ListenersForRemovalAndFocus> listenersByModel =
	//new LinkedHashMap<>();
	protected final Set<DebuggerObjectModel> models = new LinkedHashSet<>();
	protected final ForRemovalAndFocusListener forRemovalAndFocusListener =
		new ForRemovalAndFocusListener();
	protected final Map<TargetObject, TraceRecorder> recordersByTarget = new WeakHashMap<>();

	protected final ListenerSet<CollectionChangeListener<DebuggerModelFactory>> factoryListeners =
		new ListenerSet<>(CollectionChangeListener.of(DebuggerModelFactory.class), true);
	protected final ListenerSet<CollectionChangeListener<DebuggerObjectModel>> modelListeners =
		new ListenerSet<>(CollectionChangeListener.of(DebuggerObjectModel.class), true);
	protected final ListenerSet<CollectionChangeListener<TraceRecorder>> recorderListeners =
		new ListenerSet<>(CollectionChangeListener.of(TraceRecorder.class), true);
	protected final ChangeListener classChangeListener = new ChangeListenerForFactoryInstances();
	protected final ListenerOnRecorders listenerOnRecorders = new ListenerOnRecorders();

	protected final DebuggerSelectMappingOfferDialog offerDialog;
	protected final DebuggerConnectDialog connectDialog = new DebuggerConnectDialog();

	DockingAction actionDisconnectAll;

	protected DebuggerObjectModel currentModel;

	public DebuggerModelServicePlugin(PluginTool tool) {
		super(tool);
		offerDialog = new DebuggerSelectMappingOfferDialog(tool);
		ClassSearcher.addChangeListener(classChangeListener);
		refreshFactoryInstances();
		connectDialog.setModelService(this);
	}

	@Override
	protected void init() {
		super.init();

		createActions();
	}

	@Override
	protected void dispose() {
		super.dispose();

		connectDialog.dispose();
		offerDialog.dispose();
	}

	protected void createActions() {
		actionDisconnectAll = DisconnectAllAction.builder(this, this)
				.menuPath("Debugger", DisconnectAllAction.NAME)
				.menuIcon(null) // our pattern is to no use icons in the main app window
				.onAction(this::activatedDisconnectAll)
				.buildAndInstall(tool);
	}

	private void activatedDisconnectAll(ActionContext context) {
		closeAllModels();
	}

	protected void addProxy(DebuggerModelServiceProxyPlugin proxy) {
		synchronized (proxies) {
			proxies.add(proxy);
		}
	}

	protected void removeProxy(DebuggerModelServiceProxyPlugin proxy) {
		synchronized (proxies) {
			proxies.remove(proxy);
		}
	}

	@Override
	public Set<DebuggerModelFactory> getModelFactories() {
		synchronized (factories) {
			return Set.copyOf(factories);
		}
	}

	@Override
	public Set<DebuggerObjectModel> getModels() {
		synchronized (models) {
			return Set.copyOf(models);
		}
	}

	@Override
	public CompletableFuture<Void> closeAllModels() {
		AsyncFence fence = new AsyncFence();
		for (DebuggerObjectModel model : getModels()) {
			fence.include(model.close().exceptionally(showError(null, "Problem disconnecting")));
		}
		return fence.ready();
	}

	@Override
	public Collection<TraceRecorder> getTraceRecorders() {
		synchronized (recordersByTarget) {
			return List.copyOf(recordersByTarget.values());
		}
	}

	@Override
	public boolean addModel(DebuggerObjectModel model) {
		Objects.requireNonNull(model);
		synchronized (models) {
			if (!models.add(model)) {
				return false;
			}
			model.addModelListener(forRemovalAndFocusListener);
			TargetObject root = model.getModelRoot();
			// root == null, probably means we're between model construction
			// and root construction, but the model was not closed, so no need
			// to invalidate
			if (root != null && !root.isValid()) {
				forRemovalAndFocusListener.invalidated(root, root,
					"Invalidated before or during add to service");
			}
		}
		modelListeners.invoke().elementAdded(model);
		return true;
	}

	@Override
	public boolean removeModel(DebuggerObjectModel model) {
		model.removeModelListener(forRemovalAndFocusListener);
		synchronized (models) {
			if (!models.remove(model)) {
				return false;
			}
		}
		modelListeners.invoke().elementRemoved(model);
		return true;
	}

	@Override
	public void fireFocusEvent(TargetObject focused) {
		// Nothing to do
	}

	@Override
	public void fireSnapEvent(TraceRecorder recorder, long snap) {
		// Nothing to do
	}

	@Override
	public TraceRecorder recordTarget(TargetObject target, DebuggerTargetTraceMapper mapper,
			ActionSource source) throws IOException {
		TraceRecorder recorder;
		// Cannot use computeIfAbsent here
		// Entry must be present before listeners invoked
		synchronized (recordersByTarget) {
			recorder = recordersByTarget.get(target);
			if (recorder != null) {
				Msg.warn(this, "Target is already being recorded: " + target);
				return recorder;
			}
			recorder = doBeginRecording(target, mapper);
			recorder.addListener(listenerOnRecorders);
			recorder.init().exceptionally(e -> {
				if (source == ActionSource.MANUAL) {
					Msg.showError(this, null, "Record Trace", "Error initializing recorder", e);
				}
				else {
					Msg.error(this, "Error initializing recorder", e);
				}
				return null;
			});
			recordersByTarget.put(target, recorder);
		}
		recorderListeners.invoke().elementAdded(recorder);
		// NOTE: It's possible the recorder stopped recording before we installed the listener
		if (!recorder.isRecording()) {
			doRemoveRecorder(recorder);
		}
		return recorder;
	}

	@Override
	public TraceRecorder recordTargetBestOffer(TargetObject target) {
		synchronized (recordersByTarget) {
			TraceRecorder recorder = recordersByTarget.get(target);
			if (recorder != null) {
				Msg.warn(this, "Target is already being recorded: " + target);
				return recorder;
			}
		}
		DebuggerTargetTraceMapper mapper =
			DebuggerMappingOffer.first(DebuggerMappingOpinion.queryOpinions(target, false));
		if (mapper == null) {
			throw new NoSuchElementException("No mapper for target: " + target);
		}
		try {
			return recordTarget(target, mapper, ActionSource.AUTOMATIC);
		}
		catch (IOException e) {
			throw new AssertionError("Could not record target: " + target, e);
		}
	}

	@Internal
	protected TraceRecorder doRecordTargetPromptOffers(PluginTool t, TargetObject target) {
		synchronized (recordersByTarget) {
			TraceRecorder recorder = recordersByTarget.get(target);
			if (recorder != null) {
				Msg.warn(this, "Target is already being recorded: " + target);
				return recorder;
			}
		}
		List<DebuggerMappingOffer> offers = DebuggerMappingOpinion.queryOpinions(target, true);
		offerDialog.setOffers(offers);
		t.showDialog(offerDialog);
		if (offerDialog.isCancelled()) {
			return null;
		}
		DebuggerMappingOffer selected = offerDialog.getSelectedOffer();
		assert selected != null;
		DebuggerTargetTraceMapper mapper = selected.take();
		try {
			return recordTarget(target, mapper, ActionSource.MANUAL);
		}
		catch (IOException e) {
			throw new AssertionError("Could not record target: " + target, e);
			// TODO: For certain errors, It may not be appropriate to close the dialog.
		}
	}

	@Override
	public TraceRecorder recordTargetPromptOffers(TargetObject target) {
		return doRecordTargetPromptOffers(tool, target);
	}

	protected void removeRecorder(TraceRecorder recorder) {
		synchronized (recordersByTarget) {
			TraceRecorder old = recordersByTarget.remove(recorder.getTarget());
			/**
			 * Possible race condition when quickly launching and stopping a recording. If it's
			 * already removed, that's actually fine. If we get something non-null that doesn't
			 * match, then yeah, something's truly gone wrong.
			 */
			if (old != null) {
				if (old != recorder) {
					throw new AssertionError("Container-recorder mix up");
				}
				old.removeListener(listenerOnRecorders);
			}
		}
		recorderListeners.invoke().elementRemoved(recorder);
	}

	@Override
	public synchronized DebuggerObjectModel getCurrentModel() {
		if (!currentModel.isAlive()) {
			currentModel = null;

		}
		return currentModel;
	}

	@Override
	public synchronized boolean doActivateModel(DebuggerObjectModel model) {
		if (model == currentModel) {
			return false;
		}
		currentModel = model;
		return true;
	}

	@Internal
	@Override
	public void refreshFactoryInstances() {
		Collection<DebuggerModelFactory> newFactories =
			ClassSearcher.getInstances(DebuggerModelFactory.class);
		setModelFactories(newFactories);
	}

	@Internal
	@Override
	public synchronized void setModelFactories(Collection<DebuggerModelFactory> newFactories) {
		Set<DebuggerModelFactory> diff = new HashSet<>();

		diff.addAll(factories);
		diff.removeAll(newFactories);
		for (DebuggerModelFactory factory : diff) {
			factories.remove(factory);
			factoryListeners.invoke().elementRemoved(factory);
		}

		diff.clear();
		diff.addAll(newFactories);
		diff.removeAll(factories);
		for (DebuggerModelFactory factory : diff) {
			factories.add(factory);
			factoryListeners.invoke().elementAdded(factory);
		}
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
	public synchronized void addModelsChangedListener(
			CollectionChangeListener<DebuggerObjectModel> listener) {
		modelListeners.add(listener);
	}

	@Override
	public synchronized void removeModelsChangedListener(
			CollectionChangeListener<DebuggerObjectModel> listener) {
		modelListeners.remove(listener);
	}

	@Override
	public synchronized void addTraceRecordersChangedListener(
			CollectionChangeListener<TraceRecorder> listener) {
		recorderListeners.add(listener);
	}

	@Override
	public synchronized void removeTraceRecordersChangedListener(
			CollectionChangeListener<TraceRecorder> listener) {
		recorderListeners.remove(listener);
	}

	@Override
	public TraceRecorder recordTargetAndActivateTrace(TargetObject target,
			DebuggerTargetTraceMapper mapper, DebuggerTraceManagerService traceManager)
			throws IOException {
		TraceRecorder recorder = recordTarget(target, mapper, ActionSource.AUTOMATIC);
		if (traceManager != null) {
			Trace trace = recorder.getTrace();
			traceManager.openTrace(trace);
			traceManager.activate(traceManager.resolveTrace(trace),
				ActivationCause.ACTIVATE_DEFAULT);
		}
		return recorder;
	}

	@Override
	public TraceRecorder recordTargetAndActivateTrace(TargetObject target,
			DebuggerTargetTraceMapper mapper) throws IOException {
		return recordTargetAndActivateTrace(target, mapper, null);
	}

	protected TraceRecorder doBeginRecording(TargetObject target, DebuggerTargetTraceMapper mapper)
			throws IOException {
		String traceName = nameTrace(target);
		Trace trace = new DBTrace(traceName, mapper.getTraceCompilerSpec(), this);
		TraceRecorder recorder = mapper.startRecording(tool, trace);
		trace.release(this); // The recorder now owns it (on behalf of the service)
		return recorder;
	}

	protected static String nameTrace(TargetObject target) {
		String name = target.getDisplay();
		if (name == null) {
			name = PathUtils.toString(target.getPath());
		}
		CharBuffer buf = CharBuffer.wrap(name.toCharArray());
		// This duplicates makeValidName a bit, but with replacement.
		// Still use it for length check, though.
		for (int i = 0; i < buf.length(); i++) {
			if (!LocalFileSystem.isValidNameCharacter(buf.get(i))) {
				buf.put(i, '_');
			}
		}
		return AppInfo.getActiveProject()
				.getProjectData()
				.makeValidName(buf + " " + DATE_FORMAT.format(new Date()));
	}

	public void doRemoveRecorder(TraceRecorder recorder) {
		boolean removed;
		synchronized (recordersByTarget) {
			// TODO: If I register a listener. Here is where to remove it.
			removed = recordersByTarget.remove(recorder.getTarget()) != null;
		}
		if (removed) {
			recorderListeners.invoke().elementRemoved(recorder);
		}
	}

	@Override
	public TraceRecorder getRecorder(TargetObject target) {
		synchronized (recordersByTarget) {
			return recordersByTarget.get(target);
		}
	}

	@Override
	public TraceRecorder getRecorderForSuccessor(TargetObject successor) {
		synchronized (recordersByTarget) {
			while (successor != null) {
				TraceRecorder recorder = recordersByTarget.get(successor);
				if (recorder != null) {
					return recorder;
				}
				successor = successor.getParent();
			}
			return null;
		}
	}

	@Override
	public TraceRecorder getRecorder(Trace trace) {
		synchronized (recordersByTarget) {
			// TODO: Is a map of recorders by trace worth it?
			for (TraceRecorder recorder : recordersByTarget.values()) {
				if (recorder.getTrace() != trace) {
					continue;
				}
				return recorder;
			}
			return null;
		}
	}

	@Override
	public TargetThread getTargetThread(TraceThread thread) {
		TraceRecorder recorder = getRecorder(thread.getTrace());
		if (recorder == null) {
			return null;
		}
		return recorder.getTargetThread(thread);
	}

	@Override
	public TargetObject getTarget(Trace trace) {
		TraceRecorder recorder = getRecorder(trace);
		if (recorder == null) {
			return null;
		}
		return recorder.getTarget();
	}

	@Override
	public Trace getTrace(TargetObject target) {
		TraceRecorder recorder = getRecorder(target);
		if (recorder == null) {
			return null;
		}
		return recorder.getTrace();
	}

	@Override
	public TraceThread getTraceThread(TargetThread thread) {
		synchronized (recordersByTarget) {
			for (TraceRecorder recorder : recordersByTarget.values()) {
				// TODO: Consider sorting schemes to find this faster
				if (!PathUtils.isAncestor(recorder.getTarget().getPath(), thread.getPath())) {
					continue;
				}
				return recorder.getTraceThread(thread);
			}
		}
		return null;
	}

	@Override
	public TraceThread getTraceThread(TargetObject target, TargetThread thread) {
		TraceRecorder recorder = getRecorder(target);
		if (recorder == null) {
			return null;
		}
		return recorder.getTraceThread(thread);
	}

	@Override
	public TargetObject getTargetFocus(TargetObject target) {
		TraceRecorder recorder = getRecorder(target);
		if (recorder == null) {
			return null;
		}
		return recorder.getFocus();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		for (DebuggerModelFactory factory : getModelFactories()) {
			String stateName = PREFIX_FACTORY + factory.getClass().getName();
			SaveState factoryState = new SaveState();
			factory.writeConfigState(factoryState);
			saveState.putXmlElement(stateName, factoryState.saveToXml());
		}
		connectDialog.writeConfigState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		for (DebuggerModelFactory factory : getModelFactories()) {
			String stateName = PREFIX_FACTORY + factory.getClass().getName();
			Element factoryElement = saveState.getXmlElement(stateName);
			if (factoryElement != null) {
				SaveState factoryState = new SaveState(factoryElement);
				factory.readConfigState(factoryState);
			}
		}
		connectDialog.readConfigState(saveState);
	}

	protected Stream<DebuggerProgramLaunchOffer> doGetProgramLaunchOffers(PluginTool tool,
			Program program) {
		return ClassSearcher.getInstances(DebuggerProgramLaunchOpinion.class)
				.stream()
				.flatMap(opinion -> opinion.getOffers(program, tool, this).stream());
	}

	@Override
	public Stream<DebuggerProgramLaunchOffer> getProgramLaunchOffers(Program program) {
		return doGetProgramLaunchOffers(tool, program);
	}

	protected CompletableFuture<DebuggerObjectModel> doShowConnectDialog(PluginTool tool,
			DebuggerModelFactory factory, Program program) {
		CompletableFuture<DebuggerObjectModel> future = connectDialog.reset(factory, program);
		tool.showDialog(connectDialog);
		return future;
	}

	@Override
	public CompletableFuture<DebuggerObjectModel> showConnectDialog() {
		return doShowConnectDialog(tool, null, null);
	}

	@Override
	public CompletableFuture<DebuggerObjectModel> showConnectDialog(Program program) {
		return doShowConnectDialog(tool, null, program);
	}

	@Override
	public CompletableFuture<DebuggerObjectModel> showConnectDialog(DebuggerModelFactory factory) {
		return doShowConnectDialog(tool, factory, null);
	}

}
