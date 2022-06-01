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
package ghidra.app.plugin.core.debug.service.model.record;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.program.model.address.*;
import ghidra.trace.model.memory.*;
import ghidra.util.Msg;
import utilities.util.IDKeyed;

class MemoryRecorder {
	protected final ObjectBasedTraceRecorder recorder;
	protected final TraceMemoryManager memoryManager;

	protected final Map<IDKeyed<AddressSpace>, TargetMemory> memoriesByTargetSpace =
		new HashMap<>();
	protected final Map<IDKeyed<TargetMemoryRegion>, AddressRange> regions = new HashMap<>();

	protected MemoryRecorder(ObjectBasedTraceRecorder recorder) {
		this.recorder = recorder;
		this.memoryManager = recorder.trace.getMemoryManager();
	}

	private TargetMemory getMemoryForSpace(AddressSpace space) {
		return memoriesByTargetSpace.get(new IDKeyed<>(space));
	}

	private void addMemoryForSpace(AddressSpace targetSpace, TargetMemory memory) {
		TargetMemory exists =
			memoriesByTargetSpace.put(new IDKeyed<>(targetSpace), memory);
		if (exists != null && exists != memory) {
			Msg.warn(this,
				"Address space duplicated between memories: " + exists + " and " + memory);
		}
	}

	protected void addRegionMemory(TargetMemoryRegion region, TargetMemory memory) {
		addMemoryForSpace(region.getRange().getMinAddress().getAddressSpace(), memory);
	}

	protected void adjustRegionRange(TargetMemoryRegion region, AddressRange range) {
		synchronized (regions) {
			AddressRange tRange = recorder.memoryMapper.targetToTrace(range);
			if (tRange == null) {
				regions.remove(new IDKeyed<>(region));
			}
			else {
				regions.put(new IDKeyed<>(region), tRange);
			}
		}
	}

	protected void removeMemory(TargetMemory memory) {
		while (memoriesByTargetSpace.values().remove(memory))
			;
	}

	protected void removeRegion(TargetMemoryRegion region) {
		synchronized (regions) {
			regions.remove(new IDKeyed<>(region));
		}
	}

	protected CompletableFuture<byte[]> read(Address start, int length) {
		Address tStart = recorder.memoryMapper.traceToTarget(start);
		if (tStart == null) {
			return CompletableFuture.completedFuture(new byte[] {});
		}
		TargetMemory memory = getMemoryForSpace(tStart.getAddressSpace());
		if (memory == null) {
			return CompletableFuture.completedFuture(new byte[] {});
		}
		return memory.readMemory(tStart, length);
	}

	protected CompletableFuture<Void> write(Address start, byte[] data) {
		Address tStart = recorder.memoryMapper.traceToTarget(start);
		if (tStart == null) {
			throw new IllegalArgumentException(
				"Address space " + start.getAddressSpace() + " not defined on the target");
		}
		TargetMemory memory = getMemoryForSpace(tStart.getAddressSpace());
		if (memory == null) {
			throw new IllegalArgumentException(
				"Address space " + tStart.getAddressSpace() +
					" cannot be found in target memory");
		}
		return memory.writeMemory(tStart, data);
	}

	protected void invalidate(TargetMemory memory, long snap) {
		Set<AddressSpace> targetSpaces = memoriesByTargetSpace.entrySet()
				.stream()
				.filter(e -> e.getValue() == memory)
				.map(e -> e.getKey().obj)
				.collect(Collectors.toSet());
		for (AddressSpace targetSpace : targetSpaces) {
			Address traceMin = recorder.memoryMapper.targetToTrace(targetSpace.getMinAddress());
			Address traceMax = traceMin.getAddressSpace().getMaxAddress();
			memoryManager.setState(snap, traceMin, traceMax, TraceMemoryState.UNKNOWN);
		}
	}

	protected void recordMemory(long snap, Address start, byte[] data) {
		memoryManager.putBytes(snap, start, ByteBuffer.wrap(data));
	}

	public void recordError(long snap, Address tMin, DebuggerMemoryAccessException e) {
		// TODO: Bookmark to describe error?
		memoryManager.setState(snap, tMin, TraceMemoryState.ERROR);
	}

	protected boolean isAccessible(TraceMemoryRegion r) {
		// TODO: Perhaps a bit aggressive, but haven't really been checking anyway.
		return true;
	}

	public AddressSetView getAccessible() {
		synchronized (regions) {
			return regions.values()
					.stream()
					.collect(AddressCollectors.toAddressSet());
		}
	}
}
