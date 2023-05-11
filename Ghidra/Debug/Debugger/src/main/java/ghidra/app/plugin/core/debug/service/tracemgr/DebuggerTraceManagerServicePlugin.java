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
package ghidra.app.plugin.core.debug.service.tracemgr;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.ConnectException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.ControlModeChangeListener;
import ghidra.async.*;
import ghidra.async.AsyncConfigFieldCodec.BooleanAsyncConfigFieldCodec;
import ghidra.dbg.target.*;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.lifecycle.Internal;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.*;
import ghidra.util.database.DomainObjectLockHold;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.exception.*;
import ghidra.util.task.*;

//@formatter:off
@PluginInfo(
	shortDescription = "Debugger Trace Management Plugin",
	description = "Manages the set of open traces, current views, etc.",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsProduced = {
		TraceActivatedPluginEvent.class,
	},
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
		ModelObjectFocusedPluginEvent.class,
		TraceRecorderAdvancedPluginEvent.class,
		DebuggerPlatformPluginEvent.class,
	},
	servicesRequired = {},
	servicesProvided = {
		DebuggerTraceManagerService.class,
	})
//@formatter:on
public class DebuggerTraceManagerServicePlugin extends Plugin
		implements DebuggerTraceManagerService {

	private static final AutoConfigState.ClassHandler<DebuggerTraceManagerServicePlugin> //
	CONFIG_STATE_HANDLER = AutoConfigState.wireHandler(DebuggerTraceManagerServicePlugin.class,
		MethodHandles.lookup());

	private static final String KEY_TRACE_COUNT = "NUM_TRACES";
	private static final String PREFIX_OPEN_TRACE = "OPEN_TRACE_";
	private static final String KEY_CURRENT_COORDS = "CURRENT_COORDS";
	public static final String NEW_TRACES_FOLDER_NAME = "New Traces";

	class ListenerForTraceChanges extends TraceDomainObjectListener {
		private final Trace trace;

		public ListenerForTraceChanges(Trace trace) {
			this.trace = trace;
			listenFor(TraceThreadChangeType.ADDED, this::threadAdded);
			listenFor(TraceThreadChangeType.DELETED, this::threadDeleted);
			listenFor(TraceObjectChangeType.CREATED, this::objectCreated);
		}

		private void threadAdded(TraceThread thread) {
			TraceRecorder recorder = current.getRecorder();
			if (supportsFocus(recorder)) {
				// TODO: Same for stack frame? I can't imagine it's as common as this....
				if (thread == recorder.getTraceThreadForSuccessor(recorder.getFocus())) {
					activate(current.thread(thread), ActivationCause.SYNC_MODEL);
				}
				return;
			}
			if (current.getTrace() != trace) {
				return;
			}
			if (current.getThread() != null) {
				return;
			}
			activate(current.thread(thread), ActivationCause.ACTIVATE_DEFAULT);
		}

		private void threadDeleted(TraceThread thread) {
			synchronized (listenersByTrace) {
				DebuggerCoordinates last = lastCoordsByTrace.get(trace);
				if (last != null && last.getThread() == thread) {
					lastCoordsByTrace.remove(trace);
				}
			}
			if (current.getThread() == thread) {
				activate(current.thread(null), ActivationCause.ACTIVATE_DEFAULT);
			}
		}

		private void objectCreated(TraceObject object) {
			TraceRecorder recorder = current.getRecorder();
			if (supportsFocus(recorder)) {
				return;
			}
			if (current.getTrace() != trace) {
				return;
			}
			if (!object.isRoot()) {
				return;
			}
			activate(current.object(object), ActivationCause.SYNC_MODEL);
		}
	}

	static class TransactionEndFuture extends CompletableFuture<Void>
			implements TransactionListener {
		final Trace trace;

		public TransactionEndFuture(Trace trace) {
			this.trace = trace;
			this.trace.addTransactionListener(this);
			if (this.trace.getCurrentTransactionInfo() == null) {
				complete(null);
			}
		}

		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
		}

		@Override
		public boolean complete(Void value) {
			trace.removeTransactionListener(this);
			return super.complete(value);
		}

		@Override
		public void transactionEnded(DomainObjectAdapterDB domainObj) {
			complete(null);
		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
		}
	}

	// TODO: This is a bit out of this manager's bounds, but acceptable for now.
	class ForRecordersListener implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder recorder) {
			Swing.runLater(() -> updateCurrentRecorder());
		}

		public CompletableFuture<Void> waitUnlockedDebounced(TraceRecorder recorder) {
			Trace trace = recorder.getTrace();
			return new TransactionEndFuture(trace)
					.thenCompose(__ -> AsyncTimer.DEFAULT_TIMER.mark().after(100))
					.thenComposeAsync(__ -> {
						if (trace.isLocked()) {
							return waitUnlockedDebounced(recorder);
						}
						return AsyncUtils.NIL;
					});
		}

		@Override
		public void elementRemoved(TraceRecorder recorder) {
			boolean save = isSaveTracesByDefault();
			CompletableFuture<Void> flush = save
					? waitUnlockedDebounced(recorder)
					: AsyncUtils.NIL;
			flush.thenRunAsync(() -> {
				updateCurrentRecorder();
				if (!isAutoCloseOnTerminate()) {
					return;
				}
				Trace trace = recorder.getTrace();
				synchronized (listenersByTrace) {
					if (!listenersByTrace.containsKey(trace)) {
						return;
					}
				}
				if (save) {
					// Errors already handled by saveTrace
					saveTrace(trace);
				}
				closeTrace(trace);
			}, AsyncUtils.SWING_EXECUTOR);
		}
	}

	class ForFollowPresentListener implements ControlModeChangeListener {
		@Override
		public void modeChanged(Trace trace, ControlMode mode) {
			if (trace != current.getTrace() || !mode.followsPresent()) {
				return;
			}
			TraceRecorder curRecorder = current.getRecorder();
			if (curRecorder == null) {
				return;
			}
			DebuggerCoordinates coords = current;
			TargetObject focus = curRecorder.getFocus();
			if (focus != null && synchronizeActive.get()) {
				coords = coords.object(focus);
			}
			coords = coords.snap(curRecorder.getSnap());
			activateAndNotify(coords, ActivationCause.FOLLOW_PRESENT, false);
		}
	}

	protected final Map<Trace, DebuggerCoordinates> lastCoordsByTrace = new WeakHashMap<>();
	protected final Map<Trace, ListenerForTraceChanges> listenersByTrace = new WeakHashMap<>();
	protected final Set<Trace> tracesView = Collections.unmodifiableSet(listenersByTrace.keySet());

	private final ForRecordersListener forRecordersListener = new ForRecordersListener();
	private final ForFollowPresentListener forFollowPresentListener =
		new ForFollowPresentListener();

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected TargetObject curObj;
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> saveTracesByDefault = new AsyncReference<>(true);
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> synchronizeActive = new AsyncReference<>(true);
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> autoCloseOnTerminate = new AsyncReference<>(true);

	// @AutoServiceConsumed via method
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerEmulationService emulationService;
	@AutoServiceConsumed
	private DebuggerPlatformService platformService;
	// @AutoServiceConsumed via method
	private DebuggerControlService controlService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	DockingAction actionCloseTrace;
	DockingAction actionCloseAllTraces;
	DockingAction actionCloseOtherTraces;
	DockingAction actionCloseDeadTraces;
	DockingAction actionSaveTrace;
	DockingAction actionOpenTrace;
	ToggleDockingAction actionSaveByDefault;
	ToggleDockingAction actionCloseOnTerminate;
	Set<Object> strongRefs = new HashSet<>(); // Eww

	public DebuggerTraceManagerServicePlugin(PluginTool plugintool) {
		super(plugintool);
		// NOTE: Plugin should be recognized as its own service provider
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	private <T> T strongRef(T t) {
		strongRefs.add(t);
		return t;
	}

	@Override
	protected void init() {
		super.init();
		createActions();
	}

	protected void createActions() {
		actionSaveTrace = SaveTraceAction.builder(this)
				.enabledWhen(c -> current.getTrace() != null)
				.onAction(this::activatedSaveTrace)
				.buildAndInstall(tool);
		actionOpenTrace = OpenTraceAction.builder(this)
				.enabledWhen(ctx -> true)
				.onAction(this::activatedOpenTrace)
				.buildAndInstall(tool);
		actionCloseTrace = CloseTraceAction.builder(this)
				.enabledWhen(ctx -> current.getTrace() != null)
				.onAction(this::activatedCloseTrace)
				.buildAndInstall(tool);
		actionCloseAllTraces = CloseAllTracesAction.builder(this)
				.enabledWhen(ctx -> !tracesView.isEmpty())
				.onAction(this::activatedCloseAllTraces)
				.buildAndInstall(tool);
		actionCloseOtherTraces = CloseOtherTracesAction.builder(this)
				.enabledWhen(ctx -> tracesView.size() > 1 && current.getTrace() != null)
				.onAction(this::activatedCloseOtherTraces)
				.buildAndInstall(tool);
		actionCloseDeadTraces = CloseDeadTracesAction.builder(this)
				.enabledWhen(ctx -> !tracesView.isEmpty() && modelService != null)
				.onAction(this::activatedCloseDeadTraces)
				.buildAndInstall(tool);

		actionSaveByDefault = SaveByDefaultAction.builder(this)
				.selected(isSaveTracesByDefault())
				.onAction(c -> setSaveTracesByDefault(actionSaveByDefault.isSelected()))
				.buildAndInstall(tool);
		addSaveTracesByDefaultChangeListener(
			strongRef(new ToToggleSelectionListener(actionSaveByDefault)));

		actionCloseOnTerminate = CloseOnTerminateAction.builder(this)
				.selected(isAutoCloseOnTerminate())
				.onAction(c -> setAutoCloseOnTerminate(actionCloseOnTerminate.isSelected()))
				.buildAndInstall(tool);
		addAutoCloseOnTerminateChangeListener(
			strongRef(new ToToggleSelectionListener(actionCloseOnTerminate)));
	}

	private void activatedSaveTrace(ActionContext ctx) {
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		saveTrace(trace);
	}

	private void activatedOpenTrace(ActionContext ctx) {
		DomainFile df = askTrace(current.getTrace());
		if (df != null) {
			Trace trace = openTrace(df, DomainFile.DEFAULT_VERSION); // TODO: Permit opening a previous revision?
			activateTrace(trace);
		}
	}

	private void activatedCloseTrace(ActionContext ctx) {
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		closeTrace(trace);
	}

	private void activatedCloseAllTraces(ActionContext ctx) {
		closeAllTraces();
	}

	private void activatedCloseOtherTraces(ActionContext ctx) {
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		closeOtherTraces(trace);
	}

	private void activatedCloseDeadTraces(ActionContext ctx) {
		closeDeadTraces();
	}

	protected DataTreeDialog getTraceChooserDialog() {

		DomainFileFilter filter = new DomainFileFilter() {

			@Override
			public boolean accept(DomainFile df) {
				return Trace.class.isAssignableFrom(df.getDomainObjectClass());
			}

			@Override
			public boolean followLinkedFolders() {
				return false;
			}
		};

		// TODO regarding the hack note below, I believe this issue ahs been fixed, but not sure how to test
		return new DataTreeDialog(null, OpenTraceAction.NAME, DataTreeDialog.OPEN, filter) {
			{ // TODO/HACK: Why the NPE if I don't do this?
				dialogShown();
			}
		};
	}

	public DomainFile askTrace(Trace trace) {
		DataTreeDialog dialog = getTraceChooserDialog();
		if (trace != null) {
			dialog.selectDomainFile(trace.getDomainFile());
		}
		tool.showDialog(dialog);
		return dialog.getDomainFile();
	}

	@Override
	public void closeAllTraces() {
		Swing.runIfSwingOrRunLater(() -> {
			for (Trace trace : getOpenTraces()) {
				closeTrace(trace);
			}
		});
	}

	@Override
	public void closeOtherTraces(Trace keep) {
		Swing.runIfSwingOrRunLater(() -> {
			for (Trace trace : getOpenTraces()) {
				if (trace != keep) {
					closeTrace(trace);
				}
			}
		});
	}

	@Override
	public void closeDeadTraces() {
		Swing.runIfSwingOrRunLater(() -> {
			if (modelService == null) {
				return;
			}
			for (Trace trace : getOpenTraces()) {
				TraceRecorder recorder = modelService.getRecorder(trace);
				if (recorder == null) {
					closeTrace(trace);
				}
			}
		});
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeTraceRecordersChangedListener(forRecordersListener);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addTraceRecordersChangedListener(forRecordersListener);
		}
	}

	@AutoServiceConsumed
	private void setControlService(DebuggerControlService editingService) {
		if (this.controlService != null) {
			this.controlService.removeModeChangeListener(forFollowPresentListener);
		}
		this.controlService = editingService;
		if (this.controlService != null) {
			this.controlService.addModeChangeListener(forFollowPresentListener);
		}
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class<?>[] { Trace.class };
	}

	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}

		List<DomainFile> toOpen = Stream.of(data)
				.filter(f -> f != null && Trace.class.isAssignableFrom(f.getDomainObjectClass()))
				.collect(Collectors.toList());
		Collection<Trace> openTraces = openTraces(toOpen);

		if (!openTraces.isEmpty()) {
			activateTrace(openTraces.iterator().next());
			return true;
		}
		return false;
	}

	protected TraceThread threadFromTargetFocus(TraceRecorder recorder, TargetObject focus) {
		return focus == null ? null : recorder.getTraceThreadForSuccessor(focus);
	}

	protected TraceObject objectFromTargetFocus(TraceRecorder recorder, TargetObject focus) {
		return focus == null ? null
				: recorder.getTrace()
						.getObjectManager()
						.getObjectByCanonicalPath(TraceObjectKeyPath.of(focus.getPath()));
	}

	protected TraceStackFrame frameFromTargetFocus(TraceRecorder recorder, TargetObject focus) {
		return focus == null ? null : recorder.getTraceStackFrameForSuccessor(focus);
	}

	protected boolean supportsFocus(TraceRecorder recorder) {
		return recorder != null && recorder.isSupportsFocus();
	}

	protected DebuggerCoordinates fillInRecorder(Trace trace, DebuggerCoordinates coordinates) {
		if (trace == null) {
			return DebuggerCoordinates.NOWHERE;
		}
		if (coordinates.getRecorder() != null) {
			return coordinates;
		}
		TraceRecorder recorder = computeRecorder(trace);
		if (recorder == null) {
			return coordinates;
		}
		return coordinates.recorder(recorder);
	}

	protected DebuggerCoordinates fillInPlatform(DebuggerCoordinates coordinates) {
		if (platformService == null || coordinates.getTrace() == null) {
			return coordinates;
		}
		// This will emit an event, but it should have no effect
		DebuggerPlatformMapper mapper = platformService.getMapper(coordinates.getTrace(),
			coordinates.getObject(), coordinates.getSnap());
		if (mapper == null) {
			return coordinates;
		}
		TracePlatform platform =
			getPlatformForMapper(coordinates.getTrace(), coordinates.getObject(), mapper);
		return coordinates.platform(platform);
	}

	protected DebuggerCoordinates doSetCurrent(DebuggerCoordinates newCurrent,
			ActivationCause cause) {
		newCurrent = newCurrent == null ? DebuggerCoordinates.NOWHERE : newCurrent;
		newCurrent = fillInRecorder(newCurrent.getTrace(), newCurrent);
		newCurrent = fillInPlatform(newCurrent);
		if (cause == ActivationCause.START_RECORDING || cause == ActivationCause.FOLLOW_PRESENT) {
			TraceRecorder recorder = newCurrent.getRecorder();
			if (recorder != null) {
				newCurrent = newCurrent.snap(recorder.getSnap());
			}
		}
		synchronized (listenersByTrace) {
			if (current.equals(newCurrent)) {
				return null;
			}
			current = newCurrent;
			if (newCurrent.getTrace() != null) {
				lastCoordsByTrace.put(newCurrent.getTrace(), newCurrent);
			}
		}
		contextChanged();
		return newCurrent;
	}

	protected void contextChanged() {
		Trace trace = current.getTrace();
		String itemName = trace == null ? "..." : trace.getName();
		actionCloseTrace.getMenuBarData().setMenuItemName(CloseTraceAction.NAME_PREFIX + itemName);
		actionSaveTrace.getMenuBarData().setMenuItemName(SaveTraceAction.NAME_PREFIX + itemName);
		tool.contextChanged(null);
	}

	protected boolean doModelObjectFocused(TargetObject obj, boolean requirePresent) {
		curObj = obj;
		if (!synchronizeActive.get()) {
			return false;
		}
		if (requirePresent && !current.isDeadOrPresent()) {
			return false;
		}
		if (modelService == null) {
			// Bad timing could allow this
			return false;
		}
		/**
		 * TODO: Only switch if current trace belongs to the same model? There are many
		 * considerations to avoid surprise here. If the user is focused on the CLI, then we should
		 * always switch. It's harder if that CLI is outside of Ghidra.... For now, let's always
		 * switch.
		 */

		TraceRecorder recorder = modelService.getRecorderForSuccessor(obj);
		if (recorder == null) {
			return false;
		}
		Trace trace = recorder.getTrace();
		synchronized (listenersByTrace) {
			if (!listenersByTrace.containsKey(trace)) {
				return false;
			}
		}
		activateAndNotify(getCurrentFor(trace).object(obj), ActivationCause.SYNC_MODEL, false);
		return true;
	}

	private boolean isFollowsPresent(Trace trace) {
		ControlMode mode = controlService == null
				? ControlMode.DEFAULT
				: controlService.getCurrentMode(trace);
		return mode.followsPresent();
	}

	protected void doTraceRecorderAdvanced(TraceRecorder recorder, long snap) {
		Trace trace = recorder.getTrace();
		if (!isFollowsPresent(trace)) {
			return;
		}
		if (trace != current.getTrace()) {
			/**
			 * The snap needs to match upon re-activating this trace, lest it look like the user
			 * intentionally navigated to the past, causing the mode to switch away from target.
			 */
			DebuggerCoordinates inactive = null;
			synchronized (listenersByTrace) {
				DebuggerCoordinates curForTrace = getCurrentFor(trace);
				inactive = curForTrace.snapNoResolve(snap);
				lastCoordsByTrace.put(trace, inactive);
			}
			try {
				trace.getProgramView().setSnap(snap);
			}
			catch (TraceClosedException e) {
				// Whatever. Presumably, a closed event is already queued....
				Msg.warn(this, "Ignoring snapshot advance for closed trace: " + e);
			}
			firePluginEvent(new TraceInactiveCoordinatesPluginEvent(getName(), inactive));
			return;
		}
		activate(resolveSnap(snap), ActivationCause.FOLLOW_PRESENT);
	}

	protected TracePlatform getPlatformForMapper(Trace trace, TraceObject object,
			DebuggerPlatformMapper mapper) {
		return trace.getPlatformManager().getPlatform(mapper.getCompilerSpec(object));
	}

	protected void doPlatformMapperSelected(Trace trace, DebuggerPlatformMapper mapper) {
		synchronized (listenersByTrace) {
			if (!listenersByTrace.containsKey(trace)) {
				return;
			}
			DebuggerCoordinates cur =
				lastCoordsByTrace.getOrDefault(trace, DebuggerCoordinates.NOWHERE);
			DebuggerCoordinates adj =
				cur.platform(getPlatformForMapper(trace, cur.getObject(), mapper));
			lastCoordsByTrace.put(trace, adj);
			if (trace == current.getTrace()) {
				current = adj;
				fireLocationEvent(adj, ActivationCause.MAPPER_CHANGED);
			}
		}
	}

	protected TraceRecorder computeRecorder(Trace trace) {
		if (modelService == null) {
			return null;
		}
		if (trace == null) {
			return null;
		}
		return modelService.getRecorder(trace);
	}

	protected void updateCurrentRecorder() {
		TraceRecorder recorder = computeRecorder(current.getTrace());
		if (recorder == null) {
			return;
		}
		DebuggerCoordinates toActivate = current.recorder(recorder);
		if (isFollowsPresent(current.getTrace())) {
			toActivate = toActivate.snap(recorder.getSnap());
		}
		activate(toActivate, ActivationCause.FOLLOW_PRESENT);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			doSetCurrent(ev.getActiveCoordinates(), ev.getCause());
		}
		else if (event instanceof TraceClosedPluginEvent ev) {
			doTraceClosed(ev.getTrace());
		}
		else if (event instanceof ModelObjectFocusedPluginEvent ev) {
			doModelObjectFocused(ev.getFocus(), true);
		}
		else if (event instanceof TraceRecorderAdvancedPluginEvent ev) {
			// TimedMsg.debug(this, "Processing trace-advanced event");
			doTraceRecorderAdvanced(ev.getRecorder(), ev.getSnap());
		}
		else if (event instanceof DebuggerPlatformPluginEvent ev) {
			doPlatformMapperSelected(ev.getTrace(), ev.getMapper());
		}
	}

	@Override
	public synchronized Collection<Trace> getOpenTraces() {
		return Set.copyOf(tracesView);
	}

	@Override
	public DebuggerCoordinates getCurrent() {
		return current;
	}

	@Override
	public DebuggerCoordinates getCurrentFor(Trace trace) {
		synchronized (listenersByTrace) {
			// If known, fill in recorder ASAP, so it determines the time
			return fillInRecorder(trace,
				lastCoordsByTrace.getOrDefault(trace, DebuggerCoordinates.NOWHERE));
		}
	}

	@Override
	public Trace getCurrentTrace() {
		return current.getTrace();
	}

	@Override
	public TracePlatform getCurrentPlatform() {
		return current.getPlatform();
	}

	@Override
	public TraceProgramView getCurrentView() {
		return current.getView();
	}

	@Override
	public TraceThread getCurrentThread() {
		return current.getThread();
	}

	@Override
	public long getCurrentSnap() {
		return current.getSnap();
	}

	@Override
	public int getCurrentFrame() {
		return current.getFrame();
	}

	@Override
	public TraceObject getCurrentObject() {
		return current.getObject();
	}

	@Override
	public Long findSnapshot(DebuggerCoordinates coordinates) {
		if (coordinates.getTime().isSnapOnly()) {
			return coordinates.getSnap();
		}
		Trace trace = coordinates.getTrace();
		long version = trace.getEmulatorCacheVersion();
		for (TraceSnapshot snapshot : trace.getTimeManager()
				.getSnapshotsWithSchedule(coordinates.getTime())) {
			if (snapshot.getVersion() >= version) {
				return snapshot.getKey();
			}
		}
		return null;
	}

	@Override
	public CompletableFuture<Long> materialize(DebuggerCoordinates coordinates) {
		Long found = findSnapshot(coordinates);
		if (found != null) {
			return CompletableFuture.completedFuture(found);
		}
		if (emulationService == null) {
			throw new IllegalStateException(
				"Cannot navigate to coordinates with execution schedules, " +
					"because the emulation service is not available.");
		}
		return emulationService.backgroundEmulate(coordinates.getPlatform(), coordinates.getTime());
	}

	protected CompletableFuture<Void> prepareViewAndFireEvent(DebuggerCoordinates coordinates,
			ActivationCause cause) {
		TraceVariableSnapProgramView varView = (TraceVariableSnapProgramView) coordinates.getView();
		if (varView == null) { // Should only happen with NOWHERE
			fireLocationEvent(coordinates, cause);
			return AsyncUtils.NIL;
		}
		return materialize(coordinates).thenAcceptAsync(snap -> {
			if (!coordinates.equals(current)) {
				return; // We navigated elsewhere before emulation completed
			}
			varView.setSnap(snap);
			fireLocationEvent(coordinates, cause);
		}, cause == ActivationCause.EMU_STATE_EDIT
				? SwingExecutorService.MAYBE_NOW // ProgramView may call .get on Swing thread
				: SwingExecutorService.LATER); // Respect event order
	}

	protected void fireLocationEvent(DebuggerCoordinates coordinates, ActivationCause cause) {
		firePluginEvent(new TraceActivatedPluginEvent(getName(), coordinates, cause));
	}

	@Override
	public void openTrace(Trace trace) {
		if (trace.getConsumerList().contains(this)) {
			return;
		}
		trace.addConsumer(this);
		synchronized (listenersByTrace) {
			if (listenersByTrace.containsKey(trace)) {
				return;
			}
			ListenerForTraceChanges listener = new ListenerForTraceChanges(trace);
			listenersByTrace.put(trace, listener);
			trace.addListener(listener);
		}
		contextChanged();
		firePluginEvent(new TraceOpenedPluginEvent(getName(), trace));
	}

	@Override
	public Trace openTrace(DomainFile file, int version) {
		try {
			return doOpenTrace(file, version, new Object(), TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertionError(e);
		}
	}

	protected Trace doOpenTrace(DomainFile file, int version, Object consumer, TaskMonitor monitor)
			throws CancelledException {
		DomainObject obj = null;
		try {
			if (version == DomainFile.DEFAULT_VERSION) {
				obj = file.getDomainObject(consumer, true, true, monitor);
			}
			else {
				obj = file.getReadOnlyDomainObject(consumer, version, monitor);
			}
			Trace trace = (Trace) obj;
			openTrace(trace);
			return trace;
		}
		catch (VersionException e) {
			// TODO: Support upgrading
			e = new VersionException(e.getVersionIndicator(), false).combine(e);
			VersionExceptionHandler.showVersionError(null, file.getName(), file.getContentType(),
				"Open", e);
			return null;
		}
		catch (IOException e) {
			if (file.isInWritableProject()) {
				ClientUtil.handleException(tool.getProject().getRepository(), e, "Open Trace",
					null);
			}
			else {
				Msg.showError(this, null, "Error Opening Trace", "Could not open " + file.getName(),
					e);
			}
			return null;
		}
		finally {
			if (obj != null) {
				obj.release(consumer);
			}
		}
	}

	@Override
	public Collection<Trace> openTraces(Collection<DomainFile> files) {
		Collection<Trace> result = new ArrayList<>();
		new TaskLauncher(new Task("Open Traces", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				for (DomainFile f : files) {
					try {
						result.add(doOpenTrace(f, DomainFile.DEFAULT_VERSION, this, monitor));
					}
					catch (ClassCastException e) {
						Msg.error(this, "Attempted to open non-Trace domain file: " + f);
					}
				}
			}
		});
		return result;
	}

	public static DomainFolder createOrGetFolder(PluginTool tool, String operation,
			DomainFolder parent, String name) throws InvalidNameException {
		try {
			return parent.createFolder(name);
		}
		catch (DuplicateFileException e) {
			return parent.getFolder(name);
		}
		catch (NotConnectedException | ConnectException e) {
			ClientUtil.promptForReconnect(tool.getProject().getRepository(), tool.getToolFrame());
			return null;
		}
		catch (IOException e) {
			ClientUtil.handleException(tool.getProject().getRepository(), e, operation,
				tool.getToolFrame());
			return null;
		}
	}

	protected static DomainObjectLockHold maybeLock(Trace trace, boolean lock) {
		if (!lock) {
			return null;
		}
		return DomainObjectLockHold.forceLock(trace, false, "Auto Save");
	}

	public static CompletableFuture<Void> saveTrace(PluginTool tool, Trace trace, boolean force) {
		tool.prepareToSave(trace);
		CompletableFuture<Void> future = new CompletableFuture<>();
		// TODO: Get all the nuances for this correct...
		// "Save As" action, Locking, transaction flushing, etc....
		if (trace.getDomainFile().getParent() != null) {
			new TaskLauncher(new Task("Save Trace", true, true, true) {
				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					try (DomainObjectLockHold hold = maybeLock(trace, force)) {
						trace.getDomainFile().save(monitor);
						future.complete(null);
					}
					catch (CancelledException e) {
						// Done
						future.completeExceptionally(e);
					}
					catch (NotConnectedException | ConnectException e) {
						ClientUtil.promptForReconnect(tool.getProject().getRepository(),
							tool.getToolFrame());
						future.completeExceptionally(e);
					}
					catch (IOException e) {
						ClientUtil.handleException(tool.getProject().getRepository(), e,
							"Save Trace", tool.getToolFrame());
						future.completeExceptionally(e);
					}
					catch (Throwable e) {
						future.completeExceptionally(e);
					}
				}
			});
		}
		else {
			DomainFolder root = tool.getProject().getProjectData().getRootFolder();
			DomainFolder traces;
			try {
				traces = createOrGetFolder(tool, "Save New Trace", root, NEW_TRACES_FOLDER_NAME);
			}
			catch (InvalidNameException e) {
				throw new AssertionError(e);
			}

			new TaskLauncher(new Task("Save New Trace", true, true, true) {
				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					String filename = trace.getName();
					try (DomainObjectLockHold hold = maybeLock(trace, force)) {
						for (int i = 1;; i++) {
							try {
								traces.createFile(filename, trace, monitor);
								break;
							}
							catch (DuplicateFileException e) {
								filename = trace.getName() + "." + i;
							}
						}
						trace.save("Initial save", monitor);
						future.complete(null);
					}
					catch (CancelledException e) {
						// Done
						future.completeExceptionally(e);
					}
					catch (NotConnectedException | ConnectException e) {
						ClientUtil.promptForReconnect(tool.getProject().getRepository(),
							tool.getToolFrame());
						future.completeExceptionally(e);
					}
					catch (IOException e) {
						ClientUtil.handleException(tool.getProject().getRepository(), e,
							"Save New Trace", tool.getToolFrame());
						future.completeExceptionally(e);
					}
					catch (InvalidNameException e) {
						Msg.showError(DebuggerTraceManagerServicePlugin.class, null,
							"Save New Trace Error", e.getMessage());
						future.completeExceptionally(e);
					}
					catch (Throwable e) {
						Msg.showError(DebuggerTraceManagerServicePlugin.class, null,
							"Save New Trace Error", e.getMessage(), e);
						future.completeExceptionally(e);
					}
				}
			});
		}
		return future;
	}

	public CompletableFuture<Void> saveTrace(Trace trace, boolean force) {
		if (isDisposed()) {
			Msg.error(this, "Cannot save trace after manager disposal! Data may have been lost.");
			return AsyncUtils.NIL;
		}
		return saveTrace(tool, trace, force);
	}

	@Override
	public CompletableFuture<Void> saveTrace(Trace trace) {
		return saveTrace(trace, false);
	}

	protected void doTraceClosed(Trace trace) {
		synchronized (listenersByTrace) {
			trace.release(this);
			lastCoordsByTrace.remove(trace);
			trace.removeListener(listenersByTrace.remove(trace));
			//Msg.debug(this, "Remaining Consumers of " + trace + ": " + trace.getConsumerList());
		}
		if (current.getTrace() == trace) {
			activate(DebuggerCoordinates.NOWHERE, ActivationCause.ACTIVATE_DEFAULT);
		}
		else {
			contextChanged();
		}
	}

	@Override
	public void closeTrace(Trace trace) {
		/**
		 * A provider may be reading the trace, likely via the Swing thread, so schedule this on the
		 * same thread to avoid a ClosedException.
		 */
		Swing.runIfSwingOrRunLater(() -> {
			if (trace.getConsumerList().contains(this)) {
				firePluginEvent(new TraceClosedPluginEvent(getName(), trace));
				doTraceClosed(trace);
			}
		});
	}

	@Override
	protected void dispose() {
		super.dispose();
		activate(DebuggerCoordinates.NOWHERE, ActivationCause.ACTIVATE_DEFAULT);
		synchronized (listenersByTrace) {
			Iterator<Trace> it = listenersByTrace.keySet().iterator();
			while (it.hasNext()) {
				Trace trace = it.next();
				trace.release(this);
				lastCoordsByTrace.remove(trace);
				trace.removeListener(listenersByTrace.get(trace));
				it.remove();
			}
			// Be certain
			lastCoordsByTrace.clear();
		}
		autoServiceWiring.dispose();
	}

	@Internal // For debugging purposes, when needed
	private String stackTraceUp(int levels) {
		levels += 2; // account for me
		StackTraceElement elem = new Throwable().getStackTrace()[levels];
		return elem.toString();
	}

	protected static boolean isSameFocus(DebuggerCoordinates prev, DebuggerCoordinates resolved) {
		if (!Objects.equals(prev.getObject(), resolved.getObject())) {
			return false;
		}
		if (!Objects.equals(prev.getFrame(), resolved.getFrame())) {
			return false;
		}
		if (!Objects.equals(prev.getThread(), resolved.getThread())) {
			return false;
		}
		if (!Objects.equals(prev.getTrace(), resolved.getTrace())) {
			return false;
		}
		return true;
	}

	protected static TargetObject translateToTarget(DebuggerCoordinates prev,
			DebuggerCoordinates resolved) {
		if (!resolved.isAliveAndPresent()) {
			return null;
		}
		if (isSameFocus(prev, resolved)) {
			return null;
		}
		TraceRecorder recorder = resolved.getRecorder();
		TraceObject obj = resolved.getObject();
		if (obj != null) {
			TargetObject object =
				recorder.getTarget().getSuccessor(obj.getCanonicalPath().getKeyList());
			if (object != null) {
				return object;
			}
		}
		TargetStackFrame frame =
			recorder.getTargetStackFrame(resolved.getThread(), resolved.getFrame());
		if (frame != null) {
			return frame;
		}
		TargetThread thread = recorder.getTargetThread(resolved.getThread());
		if (thread != null) {
			return thread;
		}
		return recorder.getTarget();
	}

	@Override
	public CompletableFuture<Void> activateAndNotify(DebuggerCoordinates coordinates,
			ActivationCause cause, boolean syncTarget) {
		DebuggerCoordinates prev;
		DebuggerCoordinates resolved;

		Trace newTrace = coordinates.getTrace();
		synchronized (listenersByTrace) {
			if (newTrace != null && !listenersByTrace.containsKey(newTrace)) {
				throw new IllegalStateException(
					"Trace must be opened before activated: " + newTrace);
			}
		}
		prev = current;
		resolved = doSetCurrent(coordinates, cause);
		if (resolved == null) {
			return AsyncUtils.NIL;
		}
		CompletableFuture<Void> future = prepareViewAndFireEvent(resolved, cause);
		if (!syncTarget) {
			return future;
		}
		if (!synchronizeActive.get()) {
			return future;
		}
		TraceRecorder recorder = resolved.getRecorder();
		if (recorder == null) {
			return future;
		}
		TargetObject activate = translateToTarget(prev, resolved);
		if (activate == null || !activate.isValid()) {
			return future;
		}
		recorder.requestActivation(activate);
		return future;
	}

	@Override
	public void activate(DebuggerCoordinates coordinates, ActivationCause cause) {
		activateAndNotify(coordinates, cause, true); // Drop future on floor
	}

	@Override
	public DebuggerCoordinates resolveTrace(Trace trace) {
		return getCurrentFor(trace).trace(trace);
	}

	@Override
	public DebuggerCoordinates resolvePlatform(TracePlatform platform) {
		Trace trace = platform == null ? null : platform.getTrace();
		return getCurrentFor(trace).platform(platform);
	}

	@Override
	public DebuggerCoordinates resolveThread(TraceThread thread) {
		Trace trace = thread == null ? null : thread.getTrace();
		return getCurrentFor(trace).thread(thread);
	}

	@Override
	public DebuggerCoordinates resolveSnap(long snap) {
		return current.snap(snap);
	}

	@Override
	public DebuggerCoordinates resolveTime(TraceSchedule time) {
		return current.time(time);
	}

	@Override
	public DebuggerCoordinates resolveView(TraceProgramView view) {
		Trace trace = view == null ? null : view.getTrace();
		return getCurrentFor(trace).view(view);
	}

	@Override
	public DebuggerCoordinates resolveFrame(int frameLevel) {
		return current.frame(frameLevel);
	}

	@Override
	public DebuggerCoordinates resolveObject(TraceObject object) {
		return current.object(object);
	}

	@Override
	public void setSynchronizeActive(boolean enabled) {
		synchronizeActive.set(enabled, null);
		// TODO: Which action to take here, if any?
	}

	@Override
	public boolean isSynchronizeActive() {
		return synchronizeActive.get();
	}

	@Override
	public void addSynchronizeActiveChangeListener(BooleanChangeAdapter listener) {
		synchronizeActive.addChangeListener(listener);
	}

	@Override
	public void removeSynchronizeActiveChangeListener(BooleanChangeAdapter listener) {
		synchronizeActive.removeChangeListener(listener);
	}

	@Override
	public void setSaveTracesByDefault(boolean enabled) {
		saveTracesByDefault.set(enabled, null);
	}

	@Override
	public boolean isSaveTracesByDefault() {
		return saveTracesByDefault.get();
	}

	@Override
	public void addSaveTracesByDefaultChangeListener(BooleanChangeAdapter listener) {
		saveTracesByDefault.addChangeListener(listener);
	}

	@Override
	public void removeSaveTracesByDefaultChangeListener(BooleanChangeAdapter listener) {
		saveTracesByDefault.removeChangeListener(listener);
	}

	@Override
	public void setAutoCloseOnTerminate(boolean enabled) {
		autoCloseOnTerminate.set(enabled, null);
	}

	@Override
	public boolean isAutoCloseOnTerminate() {
		return autoCloseOnTerminate.get();
	}

	@Override
	public void addAutoCloseOnTerminateChangeListener(BooleanChangeAdapter listener) {
		autoCloseOnTerminate.addChangeListener(listener);
	}

	@Override
	public void removeAutoCloseOnTerminateChangeListener(BooleanChangeAdapter listener) {
		autoCloseOnTerminate.removeChangeListener(listener);
	}

	@Override
	public boolean canClose() {
		if (isSaveTracesByDefault()) {
			for (Trace trace : tracesView) {
				ProjectLocator loc = trace.getDomainFile().getProjectLocator();
				if (loc == null || loc.isTransient()) {
					saveTrace(trace);
				}
			}
		}
		return true;
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (!isSaveTracesByDefault()) {
			return;
		}
		List<Trace> traces;
		DebuggerCoordinates currentCoords;
		Map<Trace, DebuggerCoordinates> coordsByTrace;
		synchronized (listenersByTrace) {
			currentCoords = current;
			traces = tracesView.stream().filter(t -> {
				ProjectLocator loc = t.getDomainFile().getProjectLocator();
				return loc != null && !loc.isTransient();
			}).collect(Collectors.toList());
			coordsByTrace = Map.copyOf(lastCoordsByTrace);
		}

		saveState.putInt(KEY_TRACE_COUNT, traces.size());
		for (int index = 0; index < traces.size(); index++) {
			Trace t = traces.get(index);
			DebuggerCoordinates coords = coordsByTrace.get(t);
			String stateName = PREFIX_OPEN_TRACE + index;
			coords.writeDataState(tool, saveState, stateName);
		}

		currentCoords.writeDataState(tool, saveState, KEY_CURRENT_COORDS);
	}

	@Override
	public void readDataState(SaveState saveState) {
		synchronized (listenersByTrace) {
			int traceCount = saveState.getInt(KEY_TRACE_COUNT, 0);
			for (int index = 0; index < traceCount; index++) {
				String stateName = PREFIX_OPEN_TRACE + index;
				// Trace will be opened by readDataState, resolve causes update to focus and view
				DebuggerCoordinates coords =
					DebuggerCoordinates.readDataState(tool, saveState, stateName);
				if (coords.getTrace() != null) {
					lastCoordsByTrace.put(coords.getTrace(), coords);
				}
			}
		}

		activate(DebuggerCoordinates.readDataState(tool, saveState, KEY_CURRENT_COORDS),
			ActivationCause.RESTORE_STATE);
	}
}
