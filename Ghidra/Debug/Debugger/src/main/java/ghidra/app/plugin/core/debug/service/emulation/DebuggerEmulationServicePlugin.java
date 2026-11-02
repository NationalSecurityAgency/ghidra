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
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jdom2.Element;
import org.jdom2.JDOMException;

import db.Transaction;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.services.*;
import ghidra.async.AsyncLazyMap;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.modules.DebuggerStaticMappingChangeListener;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeMachine.AccessKind;
import ghidra.pcode.emu.PcodeMachine.SwiMode;
import ghidra.pcode.exec.InjectionErrorPcodeExecutionException;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.CommonSet;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.*;
import ghidra.trace.model.time.schedule.Scheduler.RunResult;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

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
	}
)
public class DebuggerEmulationServicePlugin extends Plugin implements DebuggerEmulationService {
	protected static final String KEY_DBGEMU = "DBGEMU";
	protected static final String PREFIX_DBGEMU = "DBGEMU";
	protected static final String KEY_LAST = "last";

	protected static final int MAX_CACHE_SIZE = 5;

	protected static class CacheKey implements Comparable<CacheKey> {

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

	@AutoConfigStateField
	private String defaultEmulator = DefaultEmulatorFactory.TITLE;
	protected EmulatorFactory emulatorFactory =
		new DefaultEmulatorFactory();

	protected final Set<CacheKey> eldest = new LinkedHashSet<>();
	protected final NavigableMap<CacheKey, CachedEmulator> cache = new TreeMap<>();
	protected final AsyncLazyMap<CacheKey, Long> requests =
		new AsyncLazyMap<>(new HashMap<>(), this::doBackgroundEmulate)
				.forgetErrors((_, _) -> true)
				.forgetValues((_, _) -> true);
	protected final Map<CachedEmulator, Integer> busy = new LinkedHashMap<>();
	protected final ListenerSet<EmulatorStateListener> stateListeners =
		new ListenerSet<>(EmulatorStateListener.class, true);

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
				stateListeners.invoke().running(ce);
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
				stateListeners.invoke().stopped(ce);
			}
		}

		public BusyEmu dup() {
			return new BusyEmu(ce);
		}
	}

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerTargetService targetService;
	@AutoServiceConsumed
	private DebuggerPlatformService platformService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappings;
	@AutoServiceConsumed
	private DebuggerControlService controlService;
	@AutoServiceConsumed
	private EmulationTaintInjectionService taintService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	String EMULATE_PROGRAM = "Emulate Program";
	String EMULATE_TARGET = "Emulate Target";
	String EMULATE_FUNCTION = "Emulate Function";
	String ADD_THREAD = "Add Emulated Thread to Trace";
	String INVALIDATE_CACHE = "Invalidate Emulator Cache";

	Map<Class<? extends EmulatorFactory>, ToggleDockingAction> actionsChooseEmulatorFactory =
		new HashMap<>();
	private Map<String, EmulatorFactory> emulatorMap = new HashMap<>();

	protected EmulateMultiAction emulateAction;
	// We add these to the tool independently as menu items with a null
	//  program to signal viewer dependent behavior
	protected EmulateProgramAction emulateProgramAction;
	protected EmulateFunctionAction emulateFunctionAction;

	protected SaveState toolLaunchConfigs = new SaveState();

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
		emulateAction = new EmulateMultiAction(this);
		tool.addAction(emulateAction);

		emulateProgramAction = new EmulateProgramAction(this, null);
		tool.addAction(emulateProgramAction);

		emulateFunctionAction = new EmulateFunctionAction(this, null);
		tool.addAction(emulateFunctionAction);
	}

	protected void tryEmulatorFromMode(Trace trace) {
		if (controlService != null && trace != null) {
			ControlMode mode = controlService.getCurrentMode(trace);
			emulatorFactory = emulatorMap.get(mode.name);

			if (emulatorFactory == null) {
				mode = ControlMode.EMULATOR;
				emulatorFactory = new DefaultEmulatorFactory();
				defaultEmulator = emulatorFactory.getTitle();
				controlService.setCurrentMode(trace, mode, mode.isEditable());
				return;
			}
			defaultEmulator = emulatorFactory.getTitle();
		}
	}

	@Override
	public void invalidateCache() {
		DebuggerCoordinates current = traceManager.getCurrent();
		Trace trace = current.getTrace();
		long version = trace.getEmulatorCacheVersion();
		try (Transaction _ = trace.openTransaction("Invalidate Emulator Cache")) {
			trace.setEmulatorCacheVersion(version + 1);
		}
		// Do not call clearUndo() here. This is supposed to be undoable.

		// NB. Success should already display on screen, since it's current.
		// Failure should be reported by tool's task manager.
		traceManager.materialize(current);
	}

	@Override
	public Collection<EmulatorFactory> getEmulatorFactories() {
		return ClassSearcher.getInstances(EmulatorFactory.class);
	}

	@Override
	public synchronized void setEmulatorFactory(EmulatorFactory factory) {
		emulatorFactory = Objects.requireNonNull(factory);
		defaultEmulator = emulatorFactory.getTitle();
		emulatorMap.put(defaultEmulator, factory);
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
	public synchronized EmulatorFactory getEmulatorFactory() {
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

	protected void installBreakpoints(Trace trace, long snap, PcodeMachine<?> emu) {
		Lifespan span = Lifespan.at(snap);
		TraceBreakpointManager bm = trace.getBreakpointManager();
		for (AddressSpace as : trace.getBaseAddressFactory().getAddressSpaces()) {
			for (TraceBreakpointLocation bpt : bm.getBreakpointsIntersecting(span,
				new AddressRangeImpl(as.getMinAddress(), as.getMaxAddress()))) {
				if (!bpt.isEmuEnabled(snap)) {
					continue;
				}
				Set<TraceBreakpointKind> kinds = bpt.getKinds(snap);
				if (kinds.contains(TraceBreakpointKind.HW_EXECUTE) ||
					kinds.contains(TraceBreakpointKind.SW_EXECUTE)) {
					Address minAddress = bpt.getMinAddress(snap);
					try {
						emu.inject(minAddress, bpt.getEmuSleigh(snap));
					}
					catch (Exception e) { // This is a bit broad...
						Msg.error(this, "Error compiling breakpoint Sleigh at " + minAddress, e);
						emu.inject(minAddress, "emu_injection_err();");
					}
				}
				if (kinds.equals(CommonSet.ACCESS.kinds())) {
					emu.addAccessBreakpoint(bpt.getRange(snap), AccessKind.RW);
				}
				else if (kinds.equals(CommonSet.READ.kinds())) {
					emu.addAccessBreakpoint(bpt.getRange(snap), AccessKind.R);
				}
				else if (kinds.equals(CommonSet.WRITE.kinds())) {
					emu.addAccessBreakpoint(bpt.getRange(snap), AccessKind.W);
				}
			}
		}
	}

	protected BusyEmu doEmulateFromCached(CacheKey key, TaskMonitor monitor)
			throws CancelledException {
		Trace trace = key.trace;
		TracePlatform platform = key.platform;
		TraceSchedule time = key.time;
		tryEmulatorFromMode(trace);

		TraceSnapshot tracePrefix = trace.getTimeManager().findSnapshotWithNearestPrefix(time);
		if (tracePrefix != null && tracePrefix.isSnapOnly(true)) {
			tracePrefix = null;
		}
		Map.Entry<CacheKey, CachedEmulator> cachePrefix = findNearestPrefix(key);
		if (cachePrefix != null && (tracePrefix == null ||
			cachePrefix.getKey().time.compareTo(tracePrefix.getSchedule()) >= 0)) {
			CacheKey prevKey = cachePrefix.getKey();

			Msg.debug(this, "Using cached emulator at %s".formatted(prevKey.time));

			synchronized (cache) {
				cache.remove(prevKey);
				eldest.remove(prevKey);
			}

			// TODO: Handle errors, and add to proper place in cache?
			// TODO: Finish partially-executed instructions?
			try (BusyEmu be = new BusyEmu(cachePrefix.getValue())) {
				PcodeMachine<?> emu = be.ce.emulator();

				emu.clearAllInjects();
				emu.clearAccessBreakpoints();
				emu.setSuspended(false);
				if (taintService != null) {
					taintService.injectTaint(be.ce.emulator());
				}
				installBreakpoints(key.trace, key.time.getSnap(), be.ce.emulator());

				monitor.initialize(time.totalTickCount() - prevKey.time.totalTickCount());
				createRegisterSpaces(trace, time, monitor);
				monitor.setMessage("Emulating");
				time.finish(trace, prevKey.time, emu, monitor);
				return be.dup();
			}
		}

		Target target = targetService == null ? null : targetService.getTarget(trace);
		DefaultPcodeDebuggerAccess from = new DefaultPcodeDebuggerAccess(tool, target, platform,
			tracePrefix != null ? tracePrefix.getKey() : time.getSnap(), time.getSnap());
		Writer writer = DebuggerEmulationIntegration.bytesDelayedWriteTrace(from);

		PcodeMachine<?> emu = emulatorFactory.create(from, writer);
		try (BusyEmu be = new BusyEmu(new CachedEmulator(key.trace, emu, writer))) {
			if (taintService != null) {
				taintService.injectTaint(be.ce.emulator());
			}
			installBreakpoints(key.trace, key.time.getSnap(), be.ce.emulator());
			monitor.initialize(time.totalTickCount() -
				(tracePrefix != null ? tracePrefix.getSchedule().totalTickCount() : 0));
			createRegisterSpaces(trace, time, monitor);
			monitor.setMessage("Emulating");
			if (tracePrefix != null) {
				Msg.debug(this, "Using new emulator from scratch snapshot %s"
						.formatted(tracePrefix.getScheduleString()));
				time.finish(trace, tracePrefix.getSchedule(), emu, monitor);
			}
			else {
				Msg.debug(this, "Using new emulator from snap %d".formatted(time.getSnap()));
				time.execute(trace, emu, monitor);
			}
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
		try (Transaction _ = key.trace.openTransaction("Emulate")) {
			destSnap = key.trace.getTimeManager().findScratchSnapshot(key.time);
			destSnap.setDescription("Emulated");
			try {
				PcodeTraceAccess into = new DefaultPcodeTraceAccess(key.platform, destSnap.getKey(),
					key.time.getSnap());
				ce.writer().writeDown(into);
				TraceThread lastThread = key.time.getLastThread(key.trace);
				destSnap.setEventThread(lastThread);
				destSnap.setVersion(key.trace.getEmulatorCacheVersion());
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
			if (result.schedule().hasSteps()) {
				key = new CacheKey(key.platform, key.time.dropPSteps().advanced(result.schedule()));
			}
			else {
				key = new CacheKey(key.platform, key.time.advanced(result.schedule()));
			}
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
		try (Transaction _ = trace.openTransaction("Prepare emulation")) {
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

	class TraceMappingWaiter extends CompletableFuture<Void>
			implements DebuggerStaticMappingChangeListener {
		private final Trace trace;

		public TraceMappingWaiter(Trace trace) {
			this.trace = trace;
		}

		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			if (affectedTraces.contains(trace)) {
				complete(null);
			}
		}

		public void softWait() {
			try {
				get(1, TimeUnit.SECONDS);
			}
			catch (InterruptedException | ExecutionException | TimeoutException e) {
				Msg.warn(this, "Mappings not reported by service after 1 second");
			}
		}
	}

	@Override
	public Trace launchProgram(Program program, Address address) throws IOException {
		Trace trace = null;
		try {
			trace = ProgramEmulationUtils.launchEmulationTrace(program, address, this);
			trace.flushEvents();

			TraceMappingWaiter waiter = new TraceMappingWaiter(trace);
			staticMappings.addChangeListener(waiter);
			traceManager.openTrace(trace);
			traceManager.activateTrace(trace);
			waiter.softWait();
		}
		finally {
			if (trace != null) {
				trace.release(this);
			}
		}
		return trace;
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
		tryEmulatorFromMode(trace);
		requireOpen(trace);
		return doRun(new CacheKey(platform, from), monitor, scheduler);
	}

	@Override
	public PcodeMachine<?> getCachedEmulator(Trace trace, TraceSchedule time) {
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
	private void setModelService(DebuggerTargetService targetService) {
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

	protected void executeTask(Task task) {
		ProgressService progressService = tool.getService(ProgressService.class);
		if (progressService != null) {
			progressService.execute(task);
		}
		else {
			tool.execute(task);
		}
	}

	protected static String getProgramName(Program program) {
		if (program == null) {
			return "";
		}
		DomainFile df = program.getDomainFile();
		if (df != null) {
			return df.getName();
		}
		return program.getName();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		super.readConfigState(saveState);
		SaveState read = saveState.getSaveState(KEY_DBGEMU);
		if (read != null) {
			toolLaunchConfigs = read;
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		super.writeConfigState(saveState);
		if (toolLaunchConfigs != null) {
			saveState.putSaveState(KEY_DBGEMU, toolLaunchConfigs);
		}
	}

	protected SaveState readProgramLaunchConfig(Program program, String actionName,
			boolean forPrompt) {
		SaveState state = readToolLaunchConfig(actionName);
		if (program == null) {
			return state;
		}
		ProgramUserData userData = program.getProgramUserData();
		String property = userData.getStringProperty(PREFIX_DBGEMU + actionName, null);
		if (property == null) {
			return state;
		}
		try {
			Element element = XmlUtilities.fromString(property);
			return new SaveState(element);
		}
		catch (JDOMException | IOException e) {
			if (forPrompt) {
				Msg.error(this,
					"Saved launcher args are corrupt, or launcher parameters changed. Defaulting.",
					e);
				return state;
			}
			throw new RuntimeException(
				"Saved launcher args are corrupt, or launcher parameters changed. Not launching.",
				e);
		}
	}

	protected SaveState readToolLaunchConfig(String actionName) {
		if (!toolLaunchConfigs.hasValue(actionName)) {
			return new SaveState();
		}
		return toolLaunchConfigs.getSaveState(actionName);
	}

	protected void writeProgramLaunchConfig(Program program, String actionName, SaveState state) {
		if (program == null) {
			writeToolLaunchConfig(actionName, state);
			return;
		}
		ProgramUserData userData = program.getProgramUserData();
		state.putLong(KEY_LAST, System.currentTimeMillis());
		try (Transaction _ = userData.openTransaction()) {
			Element element = state.saveToXml();
			userData.setStringProperty(PREFIX_DBGEMU + actionName, XmlUtilities.toString(element));
		}
	}

	protected void writeToolLaunchConfig(String actionName, SaveState state) {
		state.putLong(KEY_LAST, System.currentTimeMillis());
		toolLaunchConfigs.putSaveState(actionName, state);
	}

	protected record ConfigLast(String configName, long last, Program program) {}

	protected ConfigLast checkSavedConfig(Program program, ProgramUserData userData,
			String propName) {
		if (!propName.startsWith(PREFIX_DBGEMU)) {
			return null;
		}
		String configName = propName.substring(PREFIX_DBGEMU.length());
		String propVal = Objects.requireNonNull(
			userData.getStringProperty(propName, null));
		Element element;
		try {
			element = XmlUtilities.fromString(propVal);
		}
		catch (JDOMException | IOException e) {
			Msg.error(this, "Could not load launcher config for " + configName + ": " + e, e);
			return null;
		}
		return checkSavedConfig(program, configName, new SaveState(element));
	}

	protected ConfigLast checkSavedConfig(Program program, String saveName, SaveState state) {
		if (!state.hasValue(KEY_LAST)) {
			return null;
		}
		return new ConfigLast(saveName, state.getLong(KEY_LAST, 0), program);
	}

	protected Stream<ConfigLast> streamSavedConfigs(Program program) {
		if (program == null) {
			return Stream.of(toolLaunchConfigs.getNames())
					.map(n -> checkSavedConfig(null, n, toolLaunchConfigs.getSaveState(n)))
					.filter(c -> c != null);
		}
		ProgramUserData userData = program.getProgramUserData();
		return userData.getStringPropertyNames()
				.stream()
				.map(n -> checkSavedConfig(program, userData, n))
				.filter(c -> c != null);
	}

	protected ConfigLast findMostRecentConfig() {
		return Stream.concat(Stream.of(tool.getService(ProgramManager.class).getAllOpenPrograms())
				.flatMap(this::streamSavedConfigs),
			this.streamSavedConfigs(null))
				.max(Comparator.comparing(c -> c.last))
				.orElse(null);
	}

	protected Map<String, Long> loadSavedConfigs(Program program) {
		return streamSavedConfigs(program)
				.collect(Collectors.toMap(c -> c.configName(), c -> c.last()));
	}

	public DebuggerTraceManagerService getTraceManager() {
		return traceManager;
	}

	public DebuggerStaticMappingService getStaticMappings() {
		return staticMappings;
	}

	DockingActionIf getAction(String actionName) {
		List<DockingActionIf> actionList = emulateAction.getRestrictedActionList();
		for (DockingActionIf a : actionList) {
			if (a.getName().equals(actionName)) {
				return a;
			}
		}
		return null;
	}

}
