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

import static ghidra.framework.main.DataTreeDialogType.OPEN;

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
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.control.DisconnectTask;
import ghidra.app.plugin.core.debug.gui.control.TargetActionTask;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.ControlModeChangeListener;
import ghidra.async.*;
import ghidra.async.AsyncConfigFieldCodec.BooleanAsyncConfigFieldCodec;
import ghidra.dbg.target.TargetObject;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
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
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.util.TraceEvents;
import ghidra.util.*;
import ghidra.util.database.DomainObjectLockHold;
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
		TraceOpenedPluginEvent.class,
		TraceActivatedPluginEvent.class,
		TraceInactiveCoordinatesPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
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
			listenFor(TraceEvents.THREAD_ADDED, this::threadAdded);
			listenFor(TraceEvents.THREAD_DELETED, this::threadDeleted);
			listenFor(TraceEvents.OBJECT_CREATED, this::objectCreated);
		}

		private void threadAdded(TraceThread thread) {
			Target target = current.getTarget();
			if (supportsFocus(target)) {
				// TODO: Same for stack frame? I can't imagine it's as common as this....
				TraceObjectKeyPath focus = target.getFocus();
				if (focus == null) {
					return;
				}
				if (thread == target.getThreadForSuccessor(focus)) {
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
				LastCoords last = lastCoordsByTrace.get(trace);
				if (last != null && last.coords.getThread() == thread) {
					lastCoordsByTrace.remove(trace);
				}
			}
			if (current.getThread() == thread) {
				activate(current.thread(null), ActivationCause.ACTIVATE_DEFAULT);
			}
		}

		private void objectCreated(TraceObject object) {
			Target target = current.getTarget();
			if (supportsFocus(target)) {
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
	class ForTargetsListener implements TargetPublicationListener {
		@Override
		public void targetPublished(Target target) {
			Swing.runLater(() -> updateCurrentTarget());
		}

		public CompletableFuture<Void> waitUnlockedDebounced(Target target) {
			Trace trace = target.getTrace();
			return new TransactionEndFuture(trace)
					.thenCompose(__ -> AsyncTimer.DEFAULT_TIMER.mark().after(100))
					.thenComposeAsync(__ -> {
						if (trace.isLocked()) {
							return waitUnlockedDebounced(target);
						}
						return AsyncUtils.nil();
					});
		}

		@Override
		public void targetWithdrawn(Target target) {
			boolean save = isSaveTracesByDefault();
			CompletableFuture<Void> flush = save
					? waitUnlockedDebounced(target)
					: AsyncUtils.nil();
			flush.thenRunAsync(() -> {
				updateCurrentTarget();
				if (!isAutoCloseOnTerminate()) {
					return;
				}
				Trace trace = target.getTrace();
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
			Target curTarget = current.getTarget();
			if (curTarget == null) {
				return;
			}
			DebuggerCoordinates coords = current;
			TraceObjectKeyPath focus = curTarget.getFocus();
			if (focus != null) {
				coords = coords.path(focus);
			}
			coords = coords.snap(curTarget.getSnap());
			activateAndNotify(coords, ActivationCause.FOLLOW_PRESENT);
		}
	}

	protected record LastCoords(Long time, DebuggerCoordinates coords) {

		public static final LastCoords NEVER = new LastCoords(null, DebuggerCoordinates.NOWHERE);

		public LastCoords(DebuggerCoordinates coords) {
			this(System.currentTimeMillis(), coords);
		}

		public LastCoords keepTime(DebuggerCoordinates adjusted) {
			return new LastCoords(time, adjusted);
		}
	}

	protected final Map<Trace, LastCoords> lastCoordsByTrace = new WeakHashMap<>();
	protected final Map<Trace, ListenerForTraceChanges> listenersByTrace = new WeakHashMap<>();
	protected final Set<Trace> tracesView = Collections.unmodifiableSet(listenersByTrace.keySet());

	private final ForTargetsListener forTargetsListener = new ForTargetsListener();
	private final ForFollowPresentListener forFollowPresentListener =
		new ForFollowPresentListener();

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected TargetObject curObj;
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> saveTracesByDefault = new AsyncReference<>(true);
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> autoCloseOnTerminate = new AsyncReference<>(true);
	// Do not save this one, it's for testing only
	protected boolean ensureActiveTrace = true;

	// @AutoServiceConsumed via method
	private DebuggerTargetService targetService;
	@AutoServiceConsumed
	private DebuggerEmulationService emulationService;
	@AutoServiceConsumed
	private DebuggerPlatformService platformService;
	// @AutoServiceConsumed via method
	private DebuggerControlService controlService;
	@AutoServiceConsumed
	private NavigationHistoryService navigationHistoryService;
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
				.enabledWhen(ctx -> !tracesView.isEmpty() && targetService != null)
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

		return new DataTreeDialog(null, OpenTraceAction.NAME, OPEN, filter);
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
		checkCloseTraces(getOpenTraces(), false);
	}

	@Override
	public void closeOtherTraces(Trace keep) {
		checkCloseTraces(getOpenTraces().stream().filter(t -> t != keep).toList(), false);
	}

	@Override
	public void closeDeadTraces() {
		checkCloseTraces(targetService == null
				? getOpenTraces()
				: getOpenTraces().stream()
						.filter(t -> targetService.getTarget(t) == null)
						.toList(),
			false);
	}

	@AutoServiceConsumed
	private void setTargetService(DebuggerTargetService targetService) {
		if (this.targetService != null) {
			this.targetService.removeTargetPublicationListener(forTargetsListener);
		}
		this.targetService = targetService;
		if (this.targetService != null) {
			this.targetService.addTargetPublicationListener(forTargetsListener);
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

	protected boolean supportsFocus(Target target) {
		return target != null && target.isSupportsFocus();
	}

	protected DebuggerCoordinates fillInTarget(Trace trace, DebuggerCoordinates coordinates) {
		if (trace == null) {
			return DebuggerCoordinates.NOWHERE;
		}
		if (coordinates.getTarget() != null) {
			return coordinates;
		}
		Target target = computeTarget(trace);
		if (target == null) {
			return coordinates;
		}
		return coordinates.target(target);
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

	protected boolean doSetCurrent(DebuggerCoordinates newCurrent) {
		synchronized (listenersByTrace) {
			if (current.equals(newCurrent)) {
				return false;
			}
			current = newCurrent;
			if (newCurrent.getTrace() != null) {
				lastCoordsByTrace.put(newCurrent.getTrace(), new LastCoords(newCurrent));
			}
		}
		contextChanged();
		return true;
	}

	protected DebuggerCoordinates fixAndSetCurrent(DebuggerCoordinates newCurrent,
			ActivationCause cause) {
		newCurrent = newCurrent == null ? DebuggerCoordinates.NOWHERE : newCurrent;
		newCurrent = fillInTarget(newCurrent.getTrace(), newCurrent);
		newCurrent = fillInPlatform(newCurrent);
		if (cause == ActivationCause.START_RECORDING || cause == ActivationCause.FOLLOW_PRESENT) {
			Target target = newCurrent.getTarget();
			if (target != null) {
				newCurrent = newCurrent.snap(target.getSnap());
			}
		}
		newCurrent = validateCoordiantes(newCurrent, cause);
		if (newCurrent == null || !doSetCurrent(newCurrent)) {
			return null;
		}
		return newCurrent;
	}

	protected void contextChanged() {
		Trace trace = current.getTrace();
		String itemName = trace == null ? "..." : trace.getName();
		actionCloseTrace.getMenuBarData().setMenuItemName(CloseTraceAction.NAME_PREFIX + itemName);
		actionSaveTrace.getMenuBarData().setMenuItemName(SaveTraceAction.NAME_PREFIX + itemName);
		tool.contextChanged(null);
	}

	private ControlMode getEffectiveControlMode(Trace trace) {
		if (trace == null) {
			return ControlMode.RO_TRACE;
		}
		return controlService == null ? ControlMode.DEFAULT : controlService.getCurrentMode(trace);
	}

	private DebuggerCoordinates validateCoordiantes(DebuggerCoordinates coordinates,
			ActivationCause cause) {
		ControlMode mode = getEffectiveControlMode(coordinates.getTrace());
		return mode.validateCoordinates(tool, coordinates, cause);
	}

	private boolean isFollowsPresent(Trace trace) {
		ControlMode mode = getEffectiveControlMode(trace);
		return mode.followsPresent();
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
			LastCoords cur = lastCoordsByTrace.getOrDefault(trace, LastCoords.NEVER);
			DebuggerCoordinates adj =
				cur.coords.platform(getPlatformForMapper(trace, cur.coords.getObject(), mapper));
			lastCoordsByTrace.put(trace, cur.keepTime(adj));
			if (trace == current.getTrace()) {
				current = adj;
				fireLocationEvent(adj, ActivationCause.MAPPER_CHANGED);
			}
		}
	}

	protected Target computeTarget(Trace trace) {
		if (targetService == null) {
			return null;
		}
		if (trace == null) {
			return null;
		}
		return targetService.getTarget(trace);
	}

	protected void updateCurrentTarget() {
		Target target = computeTarget(current.getTrace());
		if (target == null) {
			return;
		}
		DebuggerCoordinates toActivate = current.target(target);
		activate(toActivate, ActivationCause.FOLLOW_PRESENT);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			fixAndSetCurrent(ev.getActiveCoordinates(), ev.getCause());
		}
		else if (event instanceof TraceClosedPluginEvent ev) {
			doTraceClosed(ev.getTrace());
		}
		else if (event instanceof DebuggerPlatformPluginEvent ev) {
			doPlatformMapperSelected(ev.getTrace(), ev.getMapper());
		}
	}

	@Override
	public synchronized Collection<Trace> getOpenTraces() {
		synchronized (listenersByTrace) {
			return Set.copyOf(tracesView);
		}
	}

	@Override
	public DebuggerCoordinates getCurrent() {
		return current;
	}

	@Override
	public DebuggerCoordinates getCurrentFor(Trace trace) {
		synchronized (listenersByTrace) {
			// If known, fill in target ASAP, so it determines the time
			return fillInTarget(trace,
				lastCoordsByTrace.getOrDefault(trace, LastCoords.NEVER).coords);
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
			return AsyncUtils.nil();
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
			return AsyncUtils.nil();
		}
		return saveTrace(tool, trace, force);
	}

	@Override
	public CompletableFuture<Void> saveTrace(Trace trace) {
		return saveTrace(trace, false);
	}

	protected void doTraceClosed(Trace trace) {
		if (navigationHistoryService != null) {
			navigationHistoryService.clear(trace.getProgramView());
		}
		synchronized (listenersByTrace) {
			lastCoordsByTrace.remove(trace);
			trace.removeListener(listenersByTrace.remove(trace));
			//Msg.debug(this, "Remaining Consumers of " + trace + ": " + trace.getConsumerList());
		}
		try {
			if (current.getTrace() == trace) {
				activate(DebuggerCoordinates.NOWHERE, ActivationCause.ACTIVATE_DEFAULT);
			}
			else {
				contextChanged();
			}
		}
		finally {
			trace.release(this);
		}
	}

	protected void doCloseTraces(Collection<Trace> traces, Collection<Target> targets) {
		for (Trace t : traces) {
			if (t.getConsumerList().contains(this)) {
				doTraceClosed(t);
				firePluginEvent(new TraceClosedPluginEvent(getName(), t));
			}
		}
		TargetActionTask.executeTask(tool, new DisconnectTask(tool, targets));
	}

	protected static final String MSGPAT_TERMINATE = """
			<html>
			  <body width="300px">
			    <p>This will terminate the following targets:</p>
			    <ul>
			      %s
			    </ul>
			    <p>Proceed?</p>
			  </body>
			</html>
			""";

	protected static String formatTargets(Collection<Target> targets) {
		return targets.stream()
				.map(t -> "<li>%s</li>".formatted(HTMLUtilities.escapeHTML(t.describe())))
				.sorted()
				.collect(Collectors.joining("\n"));
	}

	protected void checkCloseTraces(Collection<Trace> traces, boolean noConfirm) {
		List<Target> live =
			traces.stream()
					.map(t -> targetService.getTarget(t))
					.filter(t -> t != null)
					.toList();
		/**
		 * A provider may be reading a trace, likely via the Swing thread, so schedule this on the
		 * same thread to avoid a ClosedException.
		 */
		Swing.runIfSwingOrRunLater(() -> {
			if (live.isEmpty() || noConfirm) {
				doCloseTraces(traces, live);
				return;
			}
			String msg = MSGPAT_TERMINATE.formatted(formatTargets(live));
			int response = OptionDialog.showYesNoDialog(null, "Terminate", msg);
			switch (response) {
				case OptionDialog.YES_OPTION -> doCloseTraces(traces, live);
				case OptionDialog.NO_OPTION -> List.of();
			}
		});
	}

	@Override
	public void closeTrace(Trace trace) {
		checkCloseTraces(List.of(trace), false);
	}

	@Override
	public void closeTraceNoConfirm(Trace trace) {
		checkCloseTraces(List.of(trace), true);
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

	/**
	 * Gets the most recent coordinates among those traces still open
	 */
	protected DebuggerCoordinates getMostRecentCoordinates() {
		synchronized (listenersByTrace) {
			return lastCoordsByTrace.values()
					.stream()
					.sorted(Comparator.comparing(l -> -l.time))
					.findFirst()
					.map(l -> l.coords)
					.orElse(DebuggerCoordinates.NOWHERE);
		}
	}

	@Override
	public CompletableFuture<Void> activateAndNotify(DebuggerCoordinates coordinates,
			ActivationCause cause) {
		Trace newTrace = coordinates.getTrace();
		synchronized (listenersByTrace) {
			if (newTrace != null && !listenersByTrace.containsKey(newTrace)) {
				if (cause == ActivationCause.FOLLOW_PRESENT) {
					Msg.error(this,
						"Ignoring activation because FOLLOW_PRESENT for non-opened trace");
					return AsyncUtils.nil();
				}
				throw new IllegalStateException(
					"Trace must be opened before activated: " + newTrace);
			}
			if (newTrace == null && ensureActiveTrace) {
				coordinates = getMostRecentCoordinates(); // Might still be NOWHERE
			}
		}

		if (cause == ActivationCause.FOLLOW_PRESENT) {
			if (!isFollowsPresent(newTrace)) {
				return AsyncUtils.nil();
			}
			if (current.getTrace() != newTrace) {
				// The snap needs to match upon re-activating this trace.
				try {
					newTrace.getProgramView().setSnap(coordinates.getViewSnap());
				}
				catch (TraceClosedException e) {
					// Presumably, a closed event is queued
					Msg.warn(this, "Ignoring time activation for closed trace: " + e);
				}
				firePluginEvent(new TraceInactiveCoordinatesPluginEvent(getName(), coordinates));
				return AsyncUtils.nil();
			}
		}
		DebuggerCoordinates prev;
		DebuggerCoordinates resolved;

		prev = current;
		resolved = fixAndSetCurrent(coordinates, cause);
		if (resolved == null) {
			return AsyncUtils.nil();
		}
		CompletableFuture<Void> future =
			prepareViewAndFireEvent(resolved, cause).exceptionally(ex -> {
				// Emulation service will already display error
				doSetCurrent(prev);
				return null;
			});

		if (cause != ActivationCause.USER) {
			return future;
		}
		Target target = resolved.getTarget();
		if (target == null) {
			return future;
		}

		return future.thenCompose(__ -> target.activateAsync(prev, resolved));
	}

	@Override
	public void activate(DebuggerCoordinates coordinates, ActivationCause cause) {
		activateAndNotify(coordinates, cause); // Drop future on floor
	}

	@Override
	public DebuggerCoordinates resolveTrace(Trace trace) {
		return getCurrentFor(trace).trace(trace);
	}

	@Override
	public DebuggerCoordinates resolveTarget(Target target) {
		Trace trace = target == null ? null : target.getTrace();
		return getCurrentFor(trace).target(target).snap(target.getSnap());
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
	public DebuggerCoordinates resolvePath(TraceObjectKeyPath path) {
		return current.path(path);
	}

	@Override
	public DebuggerCoordinates resolveObject(TraceObject object) {
		return current.object(object);
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
			}).sorted(Comparator.comparingLong(t -> {
				LastCoords last = lastCoordsByTrace.get(t);
				return last == null ? -1 : last.time;
			})).toList();
			coordsByTrace = lastCoordsByTrace.entrySet()
					.stream()
					.collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue().coords));
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
			long baseTime = System.currentTimeMillis();
			int traceCount = saveState.getInt(KEY_TRACE_COUNT, 0);
			for (int index = 0; index < traceCount; index++) {
				String stateName = PREFIX_OPEN_TRACE + index;
				// Trace will be opened by readDataState, resolve causes update to focus and view
				DebuggerCoordinates coords =
					DebuggerCoordinates.readDataState(tool, saveState, stateName);
				if (coords.getTrace() != null) {
					lastCoordsByTrace.put(coords.getTrace(),
						new LastCoords(baseTime + index, coords));
				}
			}
		}

		activate(DebuggerCoordinates.readDataState(tool, saveState, KEY_CURRENT_COORDS),
			ActivationCause.RESTORE_STATE);
	}
}
