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
import java.util.concurrent.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.*;
import ghidra.async.AsyncConfigFieldCodec.BooleanAsyncConfigFieldCodec;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.*;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.lifecycle.Internal;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.*;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.exception.*;
import ghidra.util.task.*;

@PluginInfo(
	shortDescription = "Debugger Trace View Management Plugin",
	description = "Manages UI Components, Wrappers, Focus, etc.",
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
	},
	servicesRequired = {},
	servicesProvided = {
		DebuggerTraceManagerService.class,
	})
public class DebuggerTraceManagerServicePlugin extends Plugin
		implements DebuggerTraceManagerService {
	private static final AutoConfigState.ClassHandler<DebuggerTraceManagerServicePlugin> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerTraceManagerServicePlugin.class,
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
		}

		private void threadAdded(TraceThread thread) {
			TraceRecorder recorder = current.getRecorder();
			if (supportsFocus(recorder)) {
				// TODO: Same for stack frame? I can't imagine it's as common as this....
				if (thread == recorder.getTraceThreadForSuccessor(recorder.getFocus())) {
					activate(DebuggerCoordinates.thread(thread));
				}
				return;
			}
			if (current.getTrace() != trace) {
				return;
			}
			if (current.getThread() != null) {
				return;
			}
			activate(DebuggerCoordinates.thread(thread));
		}

		private void threadDeleted(TraceThread thread) {
			DebuggerCoordinates last = lastCoordsByTrace.get(trace);
			if (last != null && last.getThread() == thread) {
				lastCoordsByTrace.remove(trace);
			}
			if (current.getThread() == thread) {
				activate(DebuggerCoordinates.trace(trace));
			}
		}
	}

	// TODO: This is a bit out of this manager's bounds, but acceptable for now.
	class ForRecordersListener implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder recorder) {
			Swing.runLater(() -> updateCurrentRecorder());
		}

		@Override
		public void elementRemoved(TraceRecorder recorder) {
			Swing.runLater(() -> {
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
				if (!isSaveTracesByDefault()) {
					closeTrace(trace);
					return;
				}
				// Errors already handled by saveTrace
				tryHarder(() -> saveTrace(trace), 3, 100).thenRun(() -> closeTrace(trace));
			});
		}
	}

	protected final Map<Trace, DebuggerCoordinates> lastCoordsByTrace = new WeakHashMap<>();
	protected final Map<Trace, ListenerForTraceChanges> listenersByTrace = new WeakHashMap<>();
	protected final Set<Trace> tracesView = Collections.unmodifiableSet(listenersByTrace.keySet());

	private final ForRecordersListener forRecordersListener = new ForRecordersListener();

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected TargetObject curObj;
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> autoActivatePresent = new AsyncReference<>(true);
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> saveTracesByDefault = new AsyncReference<>(true);
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> synchronizeFocus = new AsyncReference<>(true);
	@AutoConfigStateField(codec = BooleanAsyncConfigFieldCodec.class)
	protected final AsyncReference<Boolean, Void> autoCloseOnTerminate = new AsyncReference<>(true);

	// @AutoServiceConsumed via method
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerEmulationService emulationService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private DataTreeDialog traceChooserDialog;

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

	protected <T> CompletableFuture<T> tryHarder(Supplier<CompletableFuture<T>> action, int retries,
			long retryAfterMillis) {
		Executor exe = CompletableFuture.delayedExecutor(retryAfterMillis, TimeUnit.MILLISECONDS);
		// NB. thenCompose(f -> f) also ensures exceptions are handled here, not passed through
		CompletableFuture<T> result =
			CompletableFuture.supplyAsync(action, AsyncUtils.SWING_EXECUTOR).thenCompose(f -> f);
		if (retries > 0) {
			return result.thenApply(CompletableFuture::completedFuture).exceptionally(ex -> {
				return CompletableFuture
						.supplyAsync(() -> tryHarder(action, retries - 1, retryAfterMillis), exe)
						.thenCompose(f -> f);
			}).thenCompose(f -> f);
		}
		return result;
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
		if (traceChooserDialog != null) {
			return traceChooserDialog;
		}
		DomainFileFilter filter = df -> Trace.class.isAssignableFrom(df.getDomainObjectClass());
		return traceChooserDialog =
			new DataTreeDialog(null, OpenTraceAction.NAME, DataTreeDialog.OPEN, filter) {
				{ // TODO/HACK: Why the NPE if I don't do this?
					dialogShown();
				}
			};
	}

	public DomainFile askTrace(Trace trace) {
		getTraceChooserDialog();
		if (trace != null) {
			traceChooserDialog.selectDomainFile(trace.getDomainFile());
		}
		tool.showDialog(traceChooserDialog);
		return traceChooserDialog.getDomainFile();
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

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class<?>[] { Trace.class };
	}

	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}

		List<DomainFile> toOpen = Arrays.asList(data)
				.stream()
				.filter(f -> Trace.class.isAssignableFrom(f.getDomainObjectClass()))
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

	protected TraceStackFrame frameFromTargetFocus(TraceRecorder recorder, TargetObject focus) {
		return focus == null ? null : recorder.getTraceStackFrameForSuccessor(focus);
	}

	protected boolean supportsFocus(TraceRecorder recorder) {
		return recorder != null && recorder.isSupportsFocus();
	}

	@Override
	public DebuggerCoordinates resolveCoordinates(DebuggerCoordinates coordinates) {
		if (coordinates == DebuggerCoordinates.NOWHERE) {
			return DebuggerCoordinates.NOWHERE;
		}
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			trace = current.getTrace();
		}
		if (trace == null) {
			return DebuggerCoordinates.NOWHERE;
		}
		DebuggerCoordinates lastForTrace = lastCoordsByTrace.get(trace);
		// Note: override recorder with that known to service
		TraceRecorder recorder = computeRecorder(trace);
		TargetObject focus = recorder == null ? null : recorder.getFocus();
		TraceThread thread = coordinates.getThread();
		if (thread == null) {
			if (supportsFocus(recorder)) {
				thread = threadFromTargetFocus(recorder, focus);
			}
			if (thread /*still*/ == null) { // either no focus support, or focus is not a thread
				thread = lastForTrace == null ? null : lastForTrace.getThread();
			}
			// NOTE, if still null without focus support,
			// we will take the eldest live thread at the resolved snap
		}
		/**
		 * Only select a default thread if the trace is not live. If it is live, and the model
		 * supports focus, then we should expect the debugger to control thread/frame focus.
		 * 
		 * Note: If recorder has current thread, it should already be in the threadFocusByTrace map
		 */
		// Note: override view. May not agree on snap now, but will upon activation
		TraceProgramView view = trace.getProgramView();
		TraceSchedule time = coordinates.getTime();
		if (time == null) {
			if (recorder != null && autoActivatePresent.get() && trace != current.getTrace()) {
				time = TraceSchedule.snap(recorder.getSnap());
			}
			else {
				time = lastForTrace == null ? TraceSchedule.snap(0) : lastForTrace.getTime();
			}
		}

		if (!supportsFocus(recorder)) {
			if (thread /*still*/ == null) {
				Iterator<? extends TraceThread> it =
					trace.getThreadManager().getLiveThreads(time.getSnap()).iterator();
				// docs say eldest come first
				if (it.hasNext()) {
					thread = it.next();
				}
			}
			if (thread /*STILL!?*/ == null) {
				Iterator<? extends TraceThread> it =
					trace.getThreadManager().getAllThreads().iterator();
				if (it.hasNext()) {
					thread = it.next();
				}
			}
		}

		Integer frame = coordinates.getFrame();
		if (frame == null) {
			if (supportsFocus(recorder)) {
				TraceStackFrame traceFrame = frameFromTargetFocus(recorder, focus);
				if (traceFrame == null) {
					Msg.warn(this,
						"Focus-capable model has not reported frame focus. Imposing a default");
				}
				else {
					frame = traceFrame.getLevel();
				}
			}
			if (frame /*still*/ == null && lastForTrace != null &&
				thread == lastForTrace.getThread()) {
				// TODO: Memorize frame by thread, instead of by trace?
				frame = lastForTrace.getFrame();
			}
		}
		// TODO: Is it reasonable to change back to frame 0 on snap change?
		// Only 0 (possibly synthetic) is guaranteed to exist in any snap
		if (frame == null || !time.isSnapOnly() ||
			!Objects.equals(time.getSnap(), current.getSnap())) {
			frame = 0;
		}
		return DebuggerCoordinates.all(trace, recorder, thread, view, Objects.requireNonNull(time),
			Objects.requireNonNull(frame));
	}

	protected DebuggerCoordinates doSetCurrent(DebuggerCoordinates newCurrent) {
		newCurrent = newCurrent == null ? DebuggerCoordinates.NOWHERE : newCurrent;
		synchronized (listenersByTrace) {
			DebuggerCoordinates resolved = resolveCoordinates(newCurrent);
			if (current.equals(resolved)) {
				return null;
			}
			current = resolved;
			contextChanged();
			if (resolved.getTrace() != null) {
				lastCoordsByTrace.put(resolved.getTrace(), resolved);
			}
			return resolved;
		}
	}

	protected void contextChanged() {
		Trace trace = current.getTrace();
		String name = trace == null ? "..." : trace.getName();
		actionCloseTrace.getMenuBarData().setMenuItemName(CloseTraceAction.NAME_PREFIX + name);
		actionSaveTrace.getMenuBarData().setMenuItemName(SaveTraceAction.NAME_PREFIX + name);
		tool.contextChanged(null);
	}

	protected boolean doModelObjectFocused(TargetObject obj, boolean requirePresent) {
		curObj = obj;
		if (!synchronizeFocus.get()) {
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
		TraceThread thread = threadFromTargetFocus(recorder, obj);
		long snap = recorder.getSnap();
		TraceStackFrame traceFrame = frameFromTargetFocus(recorder, obj);
		Integer frame = traceFrame == null ? null : traceFrame.getLevel();
		activateNoFocus(DebuggerCoordinates.all(trace, recorder, thread, null,
			TraceSchedule.snap(snap), frame));
		return true;
	}

	protected void doTraceRecorderAdvanced(TraceRecorder recorder, long snap) {
		if (!autoActivatePresent.get()) {
			return;
		}
		if (recorder.getTrace() != current.getTrace()) {
			// TODO: Could advance view, which might be desirable anyway
			// Would also obviate checks in resolveCoordinates and updateCurrentRecorder
			return;
		}
		activateSnap(snap);
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
		if (autoActivatePresent.get()) {
			activate(DebuggerCoordinates.recorder(recorder));
		}
		else {
			activate(current.withRecorder(recorder));
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			synchronized (listenersByTrace) {
				doSetCurrent(ev.getActiveCoordinates());
			}
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			doTraceClosed(ev.getTrace());
		}
		else if (event instanceof ModelObjectFocusedPluginEvent) {
			ModelObjectFocusedPluginEvent ev = (ModelObjectFocusedPluginEvent) event;
			doModelObjectFocused(ev.getFocus(), true);
		}
		else if (event instanceof TraceRecorderAdvancedPluginEvent) {
			TraceRecorderAdvancedPluginEvent ev = (TraceRecorderAdvancedPluginEvent) event;
			TimedMsg.debug(this, "Processing trace-advanced event");
			doTraceRecorderAdvanced(ev.getRecorder(), ev.getSnap());
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
	public Trace getCurrentTrace() {
		return current.getTrace();
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
	public TraceThread getCurrentThreadFor(Trace trace) {
		DebuggerCoordinates coords = lastCoordsByTrace.get(trace);
		return coords == null ? null : coords.getThread();
	}

	@Override
	public long getCurrentSnap() {
		return current.getSnap();
	}

	@Override
	public int getCurrentFrame() {
		return current.getFrame();
	}

	protected void prepareViewAndFireEvent(DebuggerCoordinates coordinates) {
		TraceVariableSnapProgramView varView = (TraceVariableSnapProgramView) coordinates.getView();
		if (varView == null) { // Should only happen with NOWHERE
			fireLocationEvent(coordinates);
		}
		else if (coordinates.getTime().isSnapOnly()) {
			varView.setSnap(coordinates.getSnap());
			fireLocationEvent(coordinates);
		}
		else {
			Collection<? extends TraceSnapshot> suitable = coordinates.getTrace()
					.getTimeManager()
					.getSnapshotsWithSchedule(coordinates.getTime());
			if (!suitable.isEmpty()) {
				TraceSnapshot found = suitable.iterator().next();
				varView.setSnap(found.getKey());
				fireLocationEvent(coordinates);
				return;
			}
			if (emulationService == null) {
				throw new IllegalStateException(
					"Cannot navigate to coordinates with execution schedules, " +
						"because the emulation service is not available.");
			}
			CompletableFuture<Long> bg =
				emulationService.backgroundEmulate(coordinates.getTrace(), coordinates.getTime());
			bg.thenAccept(emuSnap -> Swing.runLater(() -> {
				if (!coordinates.equals(current)) {
					return; // We navigated elsewhere before emulation completed
				}
				varView.setSnap(emuSnap);
				fireLocationEvent(coordinates);
			}));
		}
	}

	protected void fireLocationEvent(DebuggerCoordinates coordinates) {
		firePluginEvent(new TraceActivatedPluginEvent(getName(), coordinates));
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
			VersionExceptionHandler.showVersionError(null, file.getName(), file.getContentType(),
				"Open Trace", e);
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

	public static CompletableFuture<Void> saveTrace(PluginTool tool, Trace trace) {
		tool.prepareToSave(trace);
		CompletableFuture<Void> future = new CompletableFuture<>();
		// TODO: Get all the nuances for this correct...
		// "Save As" action, Locking, transaction flushing, etc....
		if (trace.getDomainFile().getParent() != null) {
			new TaskLauncher(new Task("Save Trace", true, true, true) {
				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					try {
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
			String filename = trace.getName();
			DomainFolder root = tool.getProject().getProjectData().getRootFolder();
			DomainFile existing = root.getFile(filename);
			for (int i = 1; existing != null; i++) {
				filename = trace.getName() + "." + i;
				existing = root.getFile(filename);
			}
			DomainFolder traces;
			try {
				traces = createOrGetFolder(tool, "Save New Trace", root, NEW_TRACES_FOLDER_NAME);
			}
			catch (InvalidNameException e) {
				throw new AssertionError(e);
			}

			final String finalFilename = filename;
			new TaskLauncher(new Task("Save New Trace", true, true, true) {

				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					try {
						traces.createFile(finalFilename, trace, monitor);
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

	@Override
	public CompletableFuture<Void> saveTrace(Trace trace) {
		if (isDisposed()) {
			Msg.error(this, "Cannot save trace after manager disposal! Data may have been lost.");
			return AsyncUtils.NIL;
		}
		return saveTrace(tool, trace);
	}

	protected void doTraceClosed(Trace trace) {
		synchronized (listenersByTrace) {
			trace.release(this);
			lastCoordsByTrace.remove(trace);
			trace.removeListener(listenersByTrace.remove(trace));
			//Msg.debug(this, "Remaining Consumers of " + trace + ": " + trace.getConsumerList());
		}
		if (current.getTrace() == trace) {
			activate(DebuggerCoordinates.NOWHERE);
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
		activate(DebuggerCoordinates.NOWHERE);
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

	protected void activateNoFocus(DebuggerCoordinates coordinates) {
		DebuggerCoordinates resolved = doSetCurrent(coordinates);
		if (resolved == null) {
			return;
		}
		prepareViewAndFireEvent(resolved);
	}

	protected static TargetObject translateToFocus(DebuggerCoordinates prev,
			DebuggerCoordinates resolved) {
		if (!resolved.isAliveAndPresent()) {
			return null;
		}
		TraceRecorder recorder = resolved.getRecorder();
		if (!Objects.equals(prev.getFrame(), resolved.getFrame())) {
			TargetStackFrame frame =
				recorder.getTargetStackFrame(resolved.getThread(), resolved.getFrame());
			if (frame != null) {
				return frame;
			}
		}
		if (!Objects.equals(prev.getThread(), resolved.getThread())) {
			TargetThread thread = recorder.getTargetThread(resolved.getThread());
			if (thread != null) {
				return thread;
			}
		}
		//if (!Objects.equals(prev.getTrace(), resolved.getTrace())) {
		return recorder.getTarget();
		//}
		//return null;
	}

	@Override
	public void activate(DebuggerCoordinates coordinates) {
		DebuggerCoordinates prev;
		DebuggerCoordinates resolved;
		synchronized (listenersByTrace) {
			prev = current;
			resolved = doSetCurrent(coordinates);
		}
		if (resolved == null) {
			return;
		}
		prepareViewAndFireEvent(resolved);
		if (!synchronizeFocus.get()) {
			return;
		}
		TraceRecorder recorder = resolved.getRecorder();
		if (recorder == null) {
			return;
		}
		TargetObject focus = translateToFocus(prev, resolved);
		if (focus == null || !focus.isValid()) {
			return;
		}
		recorder.requestFocus(focus);
	}

	public void activateNoFocusChange(DebuggerCoordinates coordinates) {
		//DebuggerCoordinates prev;
		DebuggerCoordinates resolved;
		synchronized (listenersByTrace) {
			//prev = current;
			resolved = doSetCurrent(coordinates);
		}
		if (resolved == null) {
			return;
		}
		prepareViewAndFireEvent(resolved);
	}

	@Override
	public void activateTrace(Trace trace) {
		activate(DebuggerCoordinates.trace(trace));
	}

	@Override
	public void activateThread(TraceThread thread) {
		activate(DebuggerCoordinates.thread(thread));
	}

	@Override
	public void activateSnap(long snap) {
		activateNoFocusChange(DebuggerCoordinates.snap(snap));
	}

	@Override
	public void activateTime(TraceSchedule time) {
		activate(DebuggerCoordinates.time(time));
	}

	@Override
	public void activateFrame(int frameLevel) {
		activate(DebuggerCoordinates.frame(frameLevel));
	}

	@Override
	public void setAutoActivatePresent(boolean enabled) {
		autoActivatePresent.set(enabled, null);
		TraceRecorder curRecorder = current.getRecorder();
		if (enabled) {
			// TODO: Re-sync focus. This wasn't working. Not sure it's appropriate anyway.
			/*if (synchronizeFocus && curRef != null) {
				if (doModelObjectFocused(curRef, false)) {
					return;
				}
			}*/
			if (curRecorder != null) {
				activateNoFocus(DebuggerCoordinates.snap(curRecorder.getSnap()));
			}
		}
	}

	@Override
	public boolean isAutoActivatePresent() {
		return autoActivatePresent.get();
	}

	@Override
	public void addAutoActivatePresentChangeListener(BooleanChangeAdapter listener) {
		autoActivatePresent.addChangeListener(listener);
	}

	@Override
	public void removeAutoActivatePresentChangeListener(BooleanChangeAdapter listener) {
		autoActivatePresent.removeChangeListener(listener);
	}

	@Override
	public void setSynchronizeFocus(boolean enabled) {
		synchronizeFocus.set(enabled, null);
		// TODO: Which action to take here, if any?
	}

	@Override
	public boolean isSynchronizeFocus() {
		return synchronizeFocus.get();
	}

	@Override
	public void addSynchronizeFocusChangeListener(BooleanChangeAdapter listener) {
		synchronizeFocus.addChangeListener(listener);
	}

	@Override
	public void removeSynchronizeFocusChangeListener(BooleanChangeAdapter listener) {
		synchronizeFocus.removeChangeListener(listener);
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
		int traceCount = saveState.getInt(KEY_TRACE_COUNT, 0);
		for (int index = 0; index < traceCount; index++) {
			String stateName = PREFIX_OPEN_TRACE + index;
			// Trace will be opened by readDataState, resolve causes update to focus and view
			DebuggerCoordinates coords =
				DebuggerCoordinates.readDataState(tool, saveState, stateName, true);
			if (coords.getTrace() != null) {
				lastCoordsByTrace.put(coords.getTrace(), coords);
			}
		}

		activate(DebuggerCoordinates.readDataState(tool, saveState, KEY_CURRENT_COORDS, false));
	}
}
