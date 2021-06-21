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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.*;
import ghidra.async.AsyncLazyMap;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.trace.model.time.TraceSchedule.CompareResult;
import ghidra.trace.model.time.TraceSnapshot;
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
		TraceClosedPluginEvent.class
	},
	servicesRequired = {
		DebuggerTraceManagerService.class
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
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	public DebuggerEmulationServicePlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	protected Map.Entry<CacheKey, CachedEmulator> findNearestPrefix(CacheKey key) {
		Map.Entry<CacheKey, CachedEmulator> candidate = cache.floorEntry(key);
		if (candidate == null) {
			return null;
		}
		if (!candidate.getKey().compareKey(key).related) {
			return null;
		}
		return candidate;
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

			cache.remove(prevKey);
			eldest.remove(prevKey);

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

		cache.put(key, ce);
		eldest.add(key);

		assert cache.size() == eldest.size();
		while (cache.size() > MAX_CACHE_SIZE) {
			CacheKey expired = eldest.iterator().next();
			eldest.remove(expired);
			cache.remove(expired);
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
}
