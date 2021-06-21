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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedMemoryRecorder;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DefaultMemoryRecorder implements ManagedMemoryRecorder {

	// For large memory captures
	private static final int BLOCK_SIZE = 4096;
	private static final long BLOCK_MASK = -1L << 12;

	protected static AddressSetView expandToBlocks(AddressSetView asv) {
		AddressSet result = new AddressSet();
		// Not terribly efficient, but this is one range most of the time
		for (AddressRange range : asv) {
			AddressSpace space = range.getAddressSpace();
			Address min = space.getAddress(range.getMinAddress().getOffset() & BLOCK_MASK);
			Address max = space.getAddress(range.getMaxAddress().getOffset() | ~BLOCK_MASK);
			result.add(new AddressRangeImpl(min, max));
		}
		return result;
	}

	private final DefaultTraceRecorder recorder;
	private final Trace trace;
	private final TraceMemoryManager memoryManager;

	public DefaultMemoryRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.memoryManager = trace.getMemoryManager();
	}

	public CompletableFuture<NavigableMap<Address, byte[]>> captureProcessMemory(AddressSetView set,
			TaskMonitor monitor) {
		// TODO: Figure out how to display/select per-thread memory.
		//   Probably need a thread parameter passed in then?
		//   NOTE: That thread memory will already be chained to process memory. Good.

		int total = 0;
		AddressSetView expSet = expandToBlocks(set)
				.intersect(trace.getMemoryManager().getRegionsAddressSet(recorder.getSnap()));
		for (AddressRange r : expSet) {
			total += Long.divideUnsigned(r.getLength() + BLOCK_SIZE - 1, BLOCK_SIZE);
		}
		monitor.initialize(total);
		monitor.setMessage("Capturing memory");
		// TODO: Read blocks in parallel? Probably NO. Tends to overload the agent.
		NavigableMap<Address, byte[]> result = new TreeMap<>();
		return AsyncUtils.each(TypeSpec.VOID, expSet.iterator(), (r, loop) -> {
			AddressRangeChunker it = new AddressRangeChunker(r, BLOCK_SIZE);
			AsyncUtils.each(TypeSpec.VOID, it.iterator(), (vRng, inner) -> {
				// The listener in the recorder will copy to the Trace.
				monitor.incrementProgress(1);
				AddressRange tRng = recorder.getMemoryMapper().traceToTarget(vRng);
				recorder.getProcessMemory()
						.readMemory(tRng.getMinAddress(), (int) tRng.getLength())
						.thenAccept(data -> result.put(tRng.getMinAddress(), data))
						.thenApply(__ -> !monitor.isCancelled())
						.handle(inner::repeatWhile);
			}).exceptionally(e -> {
				Msg.error(this, "Error reading range " + r + ": " + e);
				// NOTE: Above may double log, since recorder listens for errors, too
				return null; // Continue looping on errors
			}).thenApply(v -> !monitor.isCancelled()).handle(loop::repeatWhile);
		}).thenApply(__ -> result);
	}

	@Override
	public void offerProcessRegion(TargetMemoryRegion region) {
		TargetMemory mem = region.getMemory();
		recorder.getProcessMemory().addRegion(region, mem);
		//recorder.objectManager.addMemory(mem);
		String path = region.getJoinedPath(".");
		long snap = recorder.getSnap();
		recorder.parTx.execute("Memory region " + path + " added", () -> {
			try {
				TraceMemoryRegion traceRegion =
					memoryManager.getLiveRegionByPath(snap, path);
				if (traceRegion != null) {
					Msg.warn(this, "Region " + path + " already recorded");
					return;
				}
				traceRegion = memoryManager.addRegion(path, Range.atLeast(snap),
					recorder.getMemoryMapper().targetToTrace(region.getRange()),
					getTraceFlags(region));
				traceRegion.setName(region.getDisplay());
			}
			catch (TraceOverlappedRegionException e) {
				Msg.error(this, "Failed to create region due to overlap: " + e);
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Failed to create region due to duplicate: " + e);
			}
		}, path);
	}

	@Override
	public void removeProcessRegion(TargetMemoryRegion region) {
		// Already removed from processMemory. That's how we knew to go here.
		String path = region.getJoinedPath(".");
		long snap = recorder.getSnap();
		recorder.parTx.execute("Memory region " + path + " removed", () -> {
			try {
				TraceMemoryRegion traceRegion = memoryManager.getLiveRegionByPath(snap, path);
				if (traceRegion == null) {
					Msg.warn(this, "Could not find region " + path + " in trace to remove");
					return;
				}
				traceRegion.setDestructionSnap(snap - 1);
			}
			catch (DuplicateNameException | TraceOverlappedRegionException e) {
				// Region is shrinking in time
				Msg.error(this, "Failed to record region removal: " + e);
			}
		}, path);
	}

	@Override
	public TraceMemoryRegion getTraceMemoryRegion(TargetMemoryRegion region) {
		String path = region.getJoinedPath(".");
		return memoryManager.getLiveRegionByPath(recorder.getSnap(), path);
	}

	public Collection<TraceMemoryFlag> getTraceFlags(TargetMemoryRegion region) {
		Collection<TraceMemoryFlag> flags = new HashSet<>();
		if (region.isReadable()) {
			flags.add(TraceMemoryFlag.READ);
		}
		if (region.isWritable()) {
			flags.add(TraceMemoryFlag.WRITE);
		}
		if (region.isExecutable()) {
			flags.add(TraceMemoryFlag.EXECUTE);
		}
		// TODO: Volatile? Can any debugger report that?
		return flags;
	}

	public void regionChanged(TargetMemoryRegion region, String display) {
		String path = region.getJoinedPath(".");
		long snap = recorder.getSnap();
		recorder.parTx.execute("Memory region " + path + " changed display", () -> {
			TraceMemoryRegion traceRegion = memoryManager.getLiveRegionByPath(snap, path);
			if (traceRegion == null) {
				Msg.warn(this, "Could not find region " + path + " in trace to rename");
				return;
			}
			traceRegion.setName(display);
		}, path);
	}
}
