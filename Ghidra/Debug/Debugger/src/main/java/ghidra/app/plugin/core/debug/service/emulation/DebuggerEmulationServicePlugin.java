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
package ghidra.app.plugin.core.debug.service.emulation;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.exception.ExceptionUtils;

import db.Transaction;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;
import ghidra.async.AsyncLazyMap;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.pcode.emu.PcodeMachine.AccessKind;
import ghidra.pcode.emu.PcodeMachine.SwiMode;
import ghidra.pcode.exec.InjectionErrorPcodeExecutionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.*;
import ghidra.trace.model.time.schedule.Scheduler.RunResult;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Debugger Emulation Service Plugin",
	description = "Manages and cache trace emulation states",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceClosedPluginEvent.class,
		ProgramActivatedPluginEvent.class,
		ProgramClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerStaticMappingService.class
	},
	servicesProvided = {
		DebuggerEmulationService.class
	})
public class DebuggerEmulationServicePlugin extends Plugin implements DebuggerEmulationService {
	protected static final int MAX_CACHE_SIZE = 5;

	public interface EmulateProgramAction {
		String NAME = "Emulate Program in new Trace";
		String DESCRIPTION = "Emulate the current program in a new trace starting at the cursor";
		Icon ICON = DebuggerResources.ICON_EMULATE;
		String GROUP = DebuggerResources.GROUP_GENERAL;
		String HELP_ANCHOR = "emulate_program";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuIcon(ICON)
					.menuGroup(GROUP)
					.popupMenuPath(NAME)
					.popupMenuIcon(ICON)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface EmulateAddThreadAction {
		String NAME = "Add Emulated Thread to Trace";
		String DESCRIPTION = "Add an emulated thread to the current trace starting here";
		Icon ICON = DebuggerResources.ICON_THREAD;
		String GROUP = DebuggerResources.GROUP_GENERAL;
		String HELP_ANCHOR = "add_emulated_thread";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuIcon(ICON)
					.menuGroup(GROUP)
					.popupMenuPath(NAME)
					.popupMenuIcon(ICON)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ConfigureEmulatorAction {
		String NAME = "Configure Emulator";
		String DESCRIPTION = "Choose and configure the current emulator";
		String GROUP = DebuggerResources.GROUP_GENERAL;
		String HELP_ANCHOR = "configure_emulator";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface InvalidateEmulatorCacheAction {
		String NAME = "Invalidate Emulator Cache";
		String DESCRIPTION =
			"Prevent the emulation service from using cached snapshots from the current trace";
		String GROUP = DebuggerResources.GROUP_MAINTENANCE;
		String HELP_ANCHOR = "invalidate_cache";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, ConfigureEmulatorAction.NAME, NAME)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected static class CacheKey implements Comparable<CacheKey> {
		// TODO: Should key on platform, not trace
		protected final Trace trace;
		protected final TracePlatform platform;
		protected final TraceSchedule time;
		private final int hashCode;

		public CacheKey(TracePlatform platform, TraceSchedule time) {
			this.platform = Objects.requireNonNull(platform);
			this.trace = platform.getTrace();
			this.time = Objects.requireNonNull(time);
			this.hashCode = Objects.hash(trace, time);
		}

		@Override
		public int hashCode() {
			return hashCode;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof CacheKey)) {
				return false;
			}
			CacheKey that = (CacheKey) obj;
			if (this.trace != that.trace) {
				return false;
			}
			if (!Objects.equals(this.time, that.time)) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(CacheKey that) {
			return compareKey(that).compareTo;
		}

		public CompareResult compareKey(CacheKey that) {
			CompareResult result;

			// I don't care the order, I just care that traces matter first
			result = CompareResult.unrelated(Integer.compare(System.identityHashCode(this.trace),
				System.identityHashCode(that.trace)));
			if (result != CompareResult.EQUALS) {
				return result;
			}

			result = this.time.compareSchedule(that.time);
			if (result != CompareResult.EQUALS) {
				return result;
			}

			return CompareResult.EQUALS;
		}
	}

	protected abstract class AbstractEmulateTask<T> extends Task {
		protected final CompletableFuture<T> future = new CompletableFuture<>();

		public AbstractEmulateTask(String title, boolean hasProgress) {
			super(title, true, hasProgress, false, false);
		}

		protected abstract T compute(TaskMonitor monitor) throws CancelledException;

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				future.complete(compute(monitor));
			}
			catch (CancelledException e) {
				future.completeExceptionally(e);
				throw e;
			}
			catch (Throwable e) {
				future.completeExceptionally(e);
				ExceptionUtils.rethrow(e);
			}
		}
	}

	protected class EmulateTask extends AbstractEmulateTask<Long> {
		protected final CacheKey key;

		public EmulateTask(CacheKey key) {
			super("Emulate " + key.time + " in " + key.trace, true);
			this.key = key;
		}

		@Override
		protected Long compute(TaskMonitor monitor) throws CancelledException {
			return doEmulate(key, monitor);
		}
	}

	protected class RunEmulatorTask extends AbstractEmulateTask<EmulationResult> {
		private final CacheKey from;
		private final Scheduler scheduler;

		public RunEmulatorTask(CacheKey from, Scheduler scheduler) {
			super("Emulating...", false);
			this.from = from;
			this.scheduler = scheduler;
		}

		@Override
		protected EmulationResult compute(TaskMonitor monitor) throws CancelledException {
			EmulationResult result = doRun(from, monitor, scheduler);
			if (result.error() instanceof InjectionErrorPcodeExecutionException) {
				Msg.showError(this, null, "Breakpoint Emulation Error",
					"Compilation error in user-provided breakpoint Sleigh code.");
			}
			return result;
		}
	}

	protected DebuggerPcodeEmulatorFactory emulatorFactory =
		new BytesDebuggerPcodeEmulatorFactory();

	protected final Set<CacheKey> eldest = new LinkedHashSet<>();
	protected final NavigableMap<CacheKey, CachedEmulator> cache = new TreeMap<>();
	protected final AsyncLazyMap<CacheKey, Long> requests =
		new AsyncLazyMap<>(new HashMap<>(), this::doBackgroundEmulate)
				.forgetErrors((key, t) -> true)
				.forgetValues((key, l) -> true);
	protected final Map<CachedEmulator, Integer> busy = new LinkedHashMap<>();
	protected final ListenerSet<EmulatorStateListener> stateListeners =
		new ListenerSet<>(EmulatorStateListener.class);

	class BusyEmu implements AutoCloseable {
		private final CachedEmulator ce;

		private BusyEmu(CachedEmulator ce) {
			this.ce = ce;
			boolean fire = false;
			synchronized (busy) {
				Integer count = busy.get(ce);
				if (count == null) {
					busy.put(ce, 1);
					fire = true;
				}
				else {
					busy.put(ce, count + 1);
				}
			}
			if (fire) {
				stateListeners.fire.running(ce);
			}
		}

		@Override
		public void close() {
			boolean fire = false;
			synchronized (busy) {
				int count = busy.get(ce);
				if (count == 1) {
					busy.remove(ce);
					fire = true;
				}
				else {
					busy.put(ce, count - 1);
				}
			}
			if (fire) {
				stateListeners.fire.stopped(ce);
			}
		}

		public BusyEmu dup() {
			return new BusyEmu(ce);
		}
	}

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerPlatformService platformService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappings;
	@AutoServiceConsumed
	private DebuggerControlService controlService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	DockingAction actionEmulateProgram;
	DockingAction actionEmulateAddThread;
	DockingAction actionInvalidateCache;
	Map<Class<? extends DebuggerPcodeEmulatorFactory>, ToggleDockingAction> //
	actionsChooseEmulatorFactory = new HashMap<>();

	final ChangeListener classChangeListener = this::classesChanged;

	public DebuggerEmulationServicePlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	@Override
	protected void init() {
		super.init();
		createActions();
	}

	protected void createActions() {
		actionEmulateProgram = EmulateProgramAction.builder(this)
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(this::emulateProgramEnabled)
				.popupWhen(this::emulateProgramEnabled)
				.onAction(this::emulateProgramActivated)
				.buildAndInstall(tool);
		actionEmulateAddThread = EmulateAddThreadAction.builder(this)
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(this::emulateAddThreadEnabled)
				.popupWhen(this::emulateAddThreadEnabled)
				.onAction(this::emulateAddThreadActivated)
				.buildAndInstall(tool);
		actionInvalidateCache = InvalidateEmulatorCacheAction.builder(this)
				.enabledWhen(this::invalidateCacheEnabled)
				.onAction(this::invalidateCacheActivated)
				.buildAndInstall(tool);
		ClassSearcher.addChangeListener(classChangeListener);
		updateConfigureEmulatorStates();
	}

	private void classesChanged(ChangeEvent e) {
		updateConfigureEmulatorStates();
	}

	private ToggleDockingAction createActionChooseEmulator(DebuggerPcodeEmulatorFactory factory) {
		ToggleDockingAction action = ConfigureEmulatorAction.builder(this)
				.menuPath(DebuggerPluginPackage.NAME, ConfigureEmulatorAction.NAME,
					factory.getTitle())
				.onAction(ctx -> configureEmulatorActivated(factory))
				.buildAndInstall(tool);
		String[] path = action.getMenuBarData().getMenuPath();
		tool.setMenuGroup(Arrays.copyOf(path, path.length - 1), "zz");
		return action;
	}

	private void updateConfigureEmulatorStates() {
		Map<Class<? extends DebuggerPcodeEmulatorFactory>, DebuggerPcodeEmulatorFactory> byClass =
			getEmulatorFactories().stream()
					.collect(Collectors.toMap(DebuggerPcodeEmulatorFactory::getClass,
						Objects::requireNonNull));
		Iterator<Entry<Class<? extends DebuggerPcodeEmulatorFactory>, ToggleDockingAction>> it =
			actionsChooseEmulatorFactory.entrySet().iterator();
		while (it.hasNext()) {
			Entry<Class<? extends DebuggerPcodeEmulatorFactory>, ToggleDockingAction> ent =
				it.next();
			if (!byClass.keySet().contains(ent.getKey())) {
				tool.removeAction(ent.getValue());
			}
		}
		for (Entry<Class<? extends DebuggerPcodeEmulatorFactory>, DebuggerPcodeEmulatorFactory> ent : byClass
				.entrySet()) {
			if (!actionsChooseEmulatorFactory.containsKey(ent.getKey())) {
				ToggleDockingAction action = createActionChooseEmulator(ent.getValue());
				action.setSelected(ent.getKey() == emulatorFactory.getClass());
				actionsChooseEmulatorFactory.put(ent.getKey(), action);
			}
		}
	}

	private boolean emulateProgramEnabled(ProgramLocationActionContext ctx) {
		Program program = ctx.getProgram();
		// To avoid confusion of "forked from trace," only permit action from static context
		if (program == null || program instanceof TraceProgramView) {
			return false;
		}
		/*MemoryBlock block = program.getMemory().getBlock(ctx.getAddress());
		if (!block.isExecute()) {
			return false;
		}*/
		return true;
	}

	private void emulateProgramActivated(ProgramLocationActionContext ctx) {
		Program program = ctx.getProgram();
		if (program == null) {
			return;
		}
		Trace trace = null;
		try {
			trace = ProgramEmulationUtils.launchEmulationTrace(program, ctx.getAddress(), this);
			traceManager.openTrace(trace);
			traceManager.activateTrace(trace);
			if (controlService != null) {
				controlService.setCurrentMode(trace, ControlMode.RW_EMULATOR);
			}
		}
		catch (IOException e) {
			Msg.showError(this, null, actionEmulateProgram.getDescription(),
				"Could not create trace for emulation", e);
		}
		finally {
			if (trace != null) {
				trace.release(this);
			}
		}
	}

	private boolean emulateAddThreadEnabled(ProgramLocationActionContext ctx) {
		Program programOrView = ctx.getProgram();
		if (programOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) programOrView;
			if (!ProgramEmulationUtils.isEmulatedProgram(view.getTrace())) {
				return false;
			}
			/*MemoryBlock block = view.getMemory().getBlock(ctx.getAddress());
			return block.isExecute();*/
			return true;
		}

		// Action was probably activated in a static listing.
		// Bail if current trace is not emulated. Otherwise map and check region.
		DebuggerCoordinates current = traceManager.getCurrent();
		if (current.getTrace() == null ||
			!ProgramEmulationUtils.isEmulatedProgram(current.getTrace())) {
			return false;
		}
		TraceLocation traceLoc = staticMappings.getOpenMappedLocation(
			current.getTrace(), ctx.getLocation(), current.getSnap());
		if (traceLoc == null) {
			return false;
		}
		/*TraceMemoryRegion region = current.getTrace()
				.getMemoryManager()
				.getRegionContaining(current.getSnap(), traceLoc.getAddress());
		return region != null && region.isExecute()*/;
		return true;
	}

	private void emulateAddThreadActivated(ProgramLocationActionContext ctx) {
		Program programOrView = ctx.getProgram();
		if (programOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) programOrView;
			Trace trace = view.getTrace();
			Address tracePc = ctx.getAddress();

			/*MemoryBlock block = view.getMemory().getBlock(tracePc);
			if (!block.isExecute()) {
				return;
			}*/
			ProgramLocation progLoc =
				staticMappings.getOpenMappedLocation(new DefaultTraceLocation(view.getTrace(), null,
					Lifespan.at(view.getSnap()), tracePc));
			Program program = progLoc == null ? null : progLoc.getProgram();
			Address programPc = progLoc == null ? null : progLoc.getAddress();

			long snap =
				view.getViewport().getOrderedSnaps().stream().filter(s -> s >= 0).findFirst().get();
			TraceThread thread = ProgramEmulationUtils.launchEmulationThread(trace, snap, program,
				tracePc, programPc);
			traceManager.activateThread(thread);
		}
		else {
			Program program = programOrView;
			Address programPc = ctx.getAddress();

			DebuggerCoordinates current = traceManager.getCurrent();
			long snap = current.getSnap();
			Trace trace = current.getTrace();
			TraceLocation traceLoc =
				staticMappings.getOpenMappedLocation(trace, ctx.getLocation(), snap);
			if (traceLoc == null) {
				return;
			}
			Address tracePc = traceLoc.getAddress();
			/*TraceMemoryRegion region =
				trace.getMemoryManager().getRegionContaining(snap, tracePc);
			if (region == null || !region.isExecute()) {
				return;
			}*/
			TraceThread thread = ProgramEmulationUtils.launchEmulationThread(trace, snap, program,
				tracePc, programPc);
			traceManager.activateThread(thread);
		}
	}

	private boolean invalidateCacheEnabled(ActionContext ignored) {
		return traceManager.getCurrentTrace() != null;
	}

	private void invalidateCacheActivated(ActionContext ignored) {
		DebuggerCoordinates current = traceManager.getCurrent();
		Trace trace = current.getTrace();
		long version = trace.getEmulatorCacheVersion();
		try (Transaction tx = trace.openTransaction("Invalidate Emulator Cache")) {
			trace.setEmulatorCacheVersion(version + 1);
		}
		// Do not call clearUndo() here. This is supposed to be undoable.

		// NB. Success should already display on screen, since it's current.
		// Failure should be reported by tool's task manager.
		traceManager.materialize(current);
	}

	private void configureEmulatorActivated(DebuggerPcodeEmulatorFactory factory) {
		// TODO: Pull up config page. Tool Options? Program/Trace Options?
		setEmulatorFactory(factory);
	}

	@Override
	public Collection<DebuggerPcodeEmulatorFactory> getEmulatorFactories() {
		return ClassSearcher.getInstances(DebuggerPcodeEmulatorFactory.class);
	}

	@Override
	public synchronized void setEmulatorFactory(DebuggerPcodeEmulatorFactory factory) {
		emulatorFactory = Objects.requireNonNull(factory);
		for (ToggleDockingAction toggle : actionsChooseEmulatorFactory.values()) {
			toggle.setSelected(false);
		}
		ToggleDockingAction chosen = actionsChooseEmulatorFactory.get(factory.getClass());
		if (chosen == null) {
			// Must be special or otherwise not discovered. Could happen.
			Msg.warn(this, "An undiscovered emulator factory was set via the API: " + factory);
			return;
		}
		chosen.setSelected(true);
	}

	@Override
	public synchronized DebuggerPcodeEmulatorFactory getEmulatorFactory() {
		return emulatorFactory;
	}

	protected Map.Entry<CacheKey, CachedEmulator> findNearestPrefix(CacheKey key) {
		synchronized (cache) {
			Map.Entry<CacheKey, CachedEmulator> candidate = cache.floorEntry(key);
			if (candidate == null || !candidate.getValue().isValid()) {
				return null;
			}
			if (!candidate.getKey().compareKey(key).related) {
				return null;
			}
			return candidate;
		}
	}

	protected CompletableFuture<Long> doBackgroundEmulate(CacheKey key) {
		EmulateTask task = new EmulateTask(key);
		tool.execute(task, 500);
		return task.future;
	}

	@Override
	public CompletableFuture<Long> backgroundEmulate(TracePlatform platform, TraceSchedule time) {
		requireOpen(platform.getTrace());
		if (time.isSnapOnly()) {
			return CompletableFuture.completedFuture(time.getSnap());
		}
		return requests.get(new CacheKey(platform, time));
	}

	@Override
	public CompletableFuture<EmulationResult> backgroundRun(TracePlatform platform,
			TraceSchedule from, Scheduler scheduler) {
		requireOpen(platform.getTrace());
		CacheKey key = new CacheKey(platform, from);
		RunEmulatorTask task = new RunEmulatorTask(key, scheduler);
		tool.execute(task, 500);
		return task.future;
	}

	protected TraceSnapshot findScratch(Trace trace, TraceSchedule time) {
		Collection<? extends TraceSnapshot> exist =
			trace.getTimeManager().getSnapshotsWithSchedule(time);
		if (!exist.isEmpty()) {
			return exist.iterator().next();
		}
		/**
		 * TODO: This could be more sophisticated.... Does it need to be, though? Ideally, we'd only
		 * keep state around that has annotations, e.g., bookmarks and code units. That needs a new
		 * query (latestStartSince) on those managers, though. It must find the latest start tick
		 * since a given snap. We consider only start snaps because placed code units go "from now
		 * on out".
		 */
		TraceSnapshot last = trace.getTimeManager().getMostRecentSnapshot(-1);
		long snap = last == null ? Long.MIN_VALUE : last.getKey() + 1;
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, true);
		snapshot.setDescription("Emulated");
		snapshot.setSchedule(time);
		return snapshot;
	}

	protected void installBreakpoints(Trace trace, long snap, DebuggerPcodeMachine<?> emu) {
		Lifespan span = Lifespan.at(snap);
		TraceBreakpointManager bm = trace.getBreakpointManager();
		for (AddressSpace as : trace.getBaseAddressFactory().getAddressSpaces()) {
			for (TraceBreakpoint bpt : bm.getBreakpointsIntersecting(span,
				new AddressRangeImpl(as.getMinAddress(), as.getMaxAddress()))) {
				if (!bpt.isEmuEnabled(snap)) {
					continue;
				}
				Set<TraceBreakpointKind> kinds = bpt.getKinds();
				boolean isExecute =
					kinds.contains(TraceBreakpointKind.HW_EXECUTE) ||
						kinds.contains(TraceBreakpointKind.SW_EXECUTE);
				boolean isRead = kinds.contains(TraceBreakpointKind.READ);
				boolean isWrite = kinds.contains(TraceBreakpointKind.WRITE);
				if (isExecute) {
					try {
						emu.inject(bpt.getMinAddress(), bpt.getEmuSleigh());
					}
					catch (Exception e) { // This is a bit broad...
						Msg.error(this,
							"Error compiling breakpoint Sleigh at " + bpt.getMinAddress(), e);
						emu.inject(bpt.getMinAddress(), "emu_injection_err();");
					}
				}
				if (isRead && isWrite) {
					emu.addAccessBreakpoint(bpt.getRange(), AccessKind.RW);
				}
				else if (isRead) {
					emu.addAccessBreakpoint(bpt.getRange(), AccessKind.R);
				}
				else if (isWrite) {
					emu.addAccessBreakpoint(bpt.getRange(), AccessKind.W);
				}
			}
		}
	}

	protected BusyEmu doEmulateFromCached(CacheKey key, TaskMonitor monitor)
			throws CancelledException {
		Trace trace = key.trace;
		TracePlatform platform = key.platform;
		TraceSchedule time = key.time;

		Map.Entry<CacheKey, CachedEmulator> ancestor = findNearestPrefix(key);
		if (ancestor != null) {
			CacheKey prevKey = ancestor.getKey();

			synchronized (cache) {
				cache.remove(prevKey);
				eldest.remove(prevKey);
			}

			// TODO: Handle errors, and add to proper place in cache?
			// TODO: Finish partially-executed instructions?
			try (BusyEmu be = new BusyEmu(ancestor.getValue())) {
				DebuggerPcodeMachine<?> emu = be.ce.emulator();

				emu.clearAllInjects();
				emu.clearAccessBreakpoints();
				emu.setSuspended(false);
				installBreakpoints(key.trace, key.time.getSnap(), be.ce.emulator());

				monitor.initialize(time.totalTickCount() - prevKey.time.totalTickCount());
				createRegisterSpaces(trace, time, monitor);
				monitor.setMessage("Emulating");
				time.finish(trace, prevKey.time, emu, monitor);
				return be.dup();
			}
		}
		DebuggerPcodeMachine<?> emu = emulatorFactory.create(tool, platform, time.getSnap(),
			modelService == null ? null : modelService.getRecorder(trace));
		try (BusyEmu be = new BusyEmu(new CachedEmulator(key.trace, emu))) {
			installBreakpoints(key.trace, key.time.getSnap(), be.ce.emulator());
			monitor.initialize(time.totalTickCount());
			createRegisterSpaces(trace, time, monitor);
			monitor.setMessage("Emulating");
			time.execute(trace, emu, monitor);
			return be.dup();
		}
	}

	protected void cacheEmulator(CacheKey key, CachedEmulator ce) {
		synchronized (cache) {
			cache.put(key, ce);
			eldest.add(key);
			assert cache.size() == eldest.size();
			while (cache.size() > MAX_CACHE_SIZE) {
				CacheKey expired = eldest.iterator().next();
				eldest.remove(expired);
				cache.remove(expired);
			}
		}
	}

	protected TraceSnapshot writeToScratch(CacheKey key, CachedEmulator ce) {
		TraceSnapshot destSnap;
		try (Transaction tx = key.trace.openTransaction("Emulate")) {
			destSnap = findScratch(key.trace, key.time);
			try {
				ce.emulator().writeDown(key.platform, destSnap.getKey(), key.time.getSnap());
			}
			catch (Throwable e) {
				Msg.showError(this, null, "Emulate",
					"There was an issue writing the emulation result to the trace. " +
						"The displayed state may be inaccurate and/or incomplete.",
					e);
			}
		}
		key.trace.clearUndo();
		return destSnap;
	}

	protected long doEmulate(CacheKey key, TaskMonitor monitor) throws CancelledException {
		try (BusyEmu be = doEmulateFromCached(key, monitor)) {
			TraceSnapshot destSnap = writeToScratch(key, be.ce);
			cacheEmulator(key, be.ce);
			return destSnap.getKey();
		}
	}

	protected EmulationResult doRun(CacheKey key, TaskMonitor monitor, Scheduler scheduler)
			throws CancelledException {
		try (BusyEmu be = doEmulateFromCached(key, monitor)) {
			TraceThread eventThread = key.time.getEventThread(key.trace);
			be.ce.emulator().setSoftwareInterruptMode(SwiMode.IGNORE_STEP);
			RunResult result = scheduler.run(key.trace, eventThread, be.ce.emulator(), monitor);
			key = new CacheKey(key.platform, key.time.advanced(result.schedule()));
			Msg.info(this, "Stopped emulation at " + key.time);
			TraceSnapshot destSnap = writeToScratch(key, be.ce);
			cacheEmulator(key, be.ce);
			return new RecordEmulationResult(key.time, destSnap.getKey(), result.error());
		}
	}

	protected void createRegisterSpaces(Trace trace, TraceSchedule time, TaskMonitor monitor) {
		if (trace.getObjectManager().getRootObject() == null) {
			return;
		}
		// Cause object-register support to copy values into new register spaces
		// TODO: I wish this were not necessary
		monitor.setMessage("Creating register spaces");
		try (Transaction tx = trace.openTransaction("Prepare emulation")) {
			for (TraceThread thread : time.getThreads(trace)) {
				trace.getMemoryManager().getMemoryRegisterSpace(thread, 0, true);
			}
		}
		trace.clearUndo();
	}

	protected void requireOpen(Trace trace) {
		if (!traceManager.getOpenTraces().contains(trace)) {
			throw new IllegalArgumentException(
				"Cannot emulate a trace unless it's opened in the tool.");
		}
	}

	@Override
	public long emulate(TracePlatform platform, TraceSchedule time, TaskMonitor monitor)
			throws CancelledException {
		requireOpen(platform.getTrace());
		if (time.isSnapOnly()) {
			return time.getSnap();
		}
		return doEmulate(new CacheKey(platform, time), monitor);
	}

	@Override
	public EmulationResult run(TracePlatform platform, TraceSchedule from, TaskMonitor monitor,
			Scheduler scheduler) throws CancelledException {
		Trace trace = platform.getTrace();
		requireOpen(trace);
		return doRun(new CacheKey(platform, from), monitor, scheduler);
	}

	@Override
	public DebuggerPcodeMachine<?> getCachedEmulator(Trace trace, TraceSchedule time) {
		CachedEmulator ce =
			cache.get(new CacheKey(trace.getPlatformManager().getHostPlatform(), time));
		return ce == null || !ce.isValid() ? null : ce.emulator();
	}

	@Override
	public Collection<CachedEmulator> getBusyEmulators() {
		synchronized (busy) {
			return List.copyOf(busy.keySet());
		}
	}

	@Override
	public void addStateListener(EmulatorStateListener listener) {
		stateListeners.add(listener);
	}

	@Override
	public void removeStateListener(EmulatorStateListener listener) {
		stateListeners.remove(listener);
	}

	@AutoServiceConsumed
	private void setTraceManager(DebuggerTraceManagerService traceManager) {
		cache.clear();
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		cache.clear();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent evt = (TraceClosedPluginEvent) event;
			synchronized (cache) {
				List<CacheKey> toRemove = eldest.stream()
						.filter(k -> k.trace == evt.getTrace())
						.collect(Collectors.toList());
				cache.keySet().removeAll(toRemove);
				eldest.removeAll(toRemove);
				assert cache.size() == eldest.size();
			}
		}
	}
}
