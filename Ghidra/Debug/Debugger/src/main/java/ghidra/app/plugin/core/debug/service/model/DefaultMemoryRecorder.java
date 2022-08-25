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
import ghidra.app.plugin.core.debug.service.model.record.RecorderUtils;
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
	private static final int BLOCK_BITS = 12; // 4096 bytes

	private final DefaultTraceRecorder recorder;
	private final Trace trace;
	private final TraceMemoryManager memoryManager;

	public DefaultMemoryRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.memoryManager = trace.getMemoryManager();
	}

	public CompletableFuture<NavigableMap<Address, byte[]>> captureProcessMemory(AddressSetView set,
			TaskMonitor monitor, boolean toMap) {
		return RecorderUtils.INSTANCE.readMemoryBlocks(recorder, BLOCK_BITS, set, monitor, toMap);
	}

	@Override
	public void offerProcessMemory(TargetMemory memory) {
		recorder.getProcessMemory().addMemory(memory);
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
				AddressRange traceRange =
					recorder.getMemoryMapper().targetToTraceTruncated(region.getRange());
				if (traceRange == null) {
					Msg.warn(this, "Dropped unmappable region: " + region);
					return;
				}
				if (region.getRange().getLength() != traceRange.getLength()) {
					Msg.warn(this, "Truncated region: " + region);
				}
				traceRegion = memoryManager.addRegion(path, Range.atLeast(snap), traceRange,
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
	public void removeProcessMemory(TargetMemory memory) {
		recorder.getProcessMemory().removeMemory(memory);
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
