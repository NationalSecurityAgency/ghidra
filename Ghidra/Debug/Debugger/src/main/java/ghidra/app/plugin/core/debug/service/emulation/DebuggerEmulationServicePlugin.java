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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.collect.Range;

import docking.action.DockingAction;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.EmulateAddThreadAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.EmulateProgramAction;
import ghidra.app.services.*;
import ghidra.async.AsyncLazyMap;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.trace.model.time.TraceSchedule.CompareResult;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Debugger Emulation Service Plugin",
	description = "Manages and cache trace emulation states",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.UNSTABLE,
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
	protected static long nextSnap = Long.MIN_VALUE; // HACK

	protected static class CacheKey implements Comparable<CacheKey> {
		protected final Trace trace;
		protected final TraceSchedule time;

		public CacheKey(Trace trace, TraceSchedule time) {
			this.trace = trace;
			this.time = time;
		}

		@Override
		public int hashCode() {
			return Objects.hash(trace, time);
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

	protected static class CachedEmulator {
		final DebuggerTracePcodeEmulator emulator;

		public CachedEmulator(DebuggerTracePcodeEmulator emulator) {
			this.emulator = emulator;
		}
	}

	protected class EmulateTask extends Task {
		protected final CacheKey key;
		protected final CompletableFuture<Long> future = new CompletableFuture<>();

		public EmulateTask(CacheKey key) {
			super("Emulate " + key.time + " in " + key.trace, true, true, false, false);
			this.key = key;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				future.complete(doEmulate(key, monitor));
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

	protected final Set<CacheKey> eldest = new LinkedHashSet<>();
	protected final NavigableMap<CacheKey, CachedEmulator> cache = new TreeMap<>();
	protected final AsyncLazyMap<CacheKey, Long> requests =
		new AsyncLazyMap<>(new HashMap<>(), this::doBackgroundEmulate)
				.forgetErrors((key, t) -> true)
				.forgetValues((key, l) -> true);

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappings;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	DockingAction actionEmulateProgram;
	DockingAction actionEmulateAddThread;

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
					Range.singleton(view.getSnap()), tracePc));
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

	protected Map.Entry<CacheKey, CachedEmulator> findNearestPrefix(CacheKey key) {
		synchronized (cache) {
			Map.Entry<CacheKey, CachedEmulator> candidate = cache.floorEntry(key);
			if (candidate == null) {
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
	public CompletableFuture<Long> backgroundEmulate(Trace trace, TraceSchedule time) {
		if (!traceManager.getOpenTraces().contains(trace)) {
			throw new IllegalArgumentException(
				"Cannot emulate a trace unless it's opened in the tool.");
		}
		if (time.isSnapOnly()) {
			return CompletableFuture.completedFuture(time.getSnap());
		}
		return requests.get(new CacheKey(trace, time));
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

	protected long doEmulate(CacheKey key, TaskMonitor monitor) throws CancelledException {
		Trace trace = key.trace;
		TraceSchedule time = key.time;
		CachedEmulator ce;
		DebuggerTracePcodeEmulator emu;
		Map.Entry<CacheKey, CachedEmulator> ancestor = findNearestPrefix(key);
		if (ancestor != null) {
			CacheKey prevKey = ancestor.getKey();

			synchronized (cache) {
				cache.remove(prevKey);
				eldest.remove(prevKey);
			}

			// TODO: Handle errors, and add to proper place in cache?
			// TODO: Finish partially-executed instructions?
			ce = ancestor.getValue();
			emu = ce.emulator;
			monitor.initialize(time.totalTickCount() - prevKey.time.totalTickCount());
			time.finish(trace, prevKey.time, emu, monitor);
		}
		else {
			emu = new DebuggerTracePcodeEmulator(tool, trace, time.getSnap(),
				modelService == null ? null : modelService.getRecorder(trace));
			ce = new CachedEmulator(emu);
			monitor.initialize(time.totalTickCount());
			time.execute(trace, emu, monitor);
		}
		TraceSnapshot destSnap;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Emulate", true)) {
			destSnap = findScratch(trace, time);
			emu.writeDown(trace, destSnap.getKey(), time.getSnap(), false);
		}

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

		return destSnap.getKey();
	}

	@Override
	public long emulate(Trace trace, TraceSchedule time, TaskMonitor monitor)
			throws CancelledException {
		if (!traceManager.getOpenTraces().contains(trace)) {
			throw new IllegalArgumentException(
				"Cannot emulate a trace unless it's opened in the tool.");
		}
		if (time.isSnapOnly()) {
			return time.getSnap();
		}
		return doEmulate(new CacheKey(trace, time), monitor);
	}

	@Override
	public DebuggerTracePcodeEmulator getCachedEmulator(Trace trace, TraceSchedule time) {
		CachedEmulator ce = cache.get(new CacheKey(trace, time));
		return ce == null ? null : ce.emulator;
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
