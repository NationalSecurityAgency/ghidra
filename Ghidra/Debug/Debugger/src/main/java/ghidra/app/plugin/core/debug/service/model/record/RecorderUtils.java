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

import java.util.concurrent.CompletableFuture;

import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public enum RecorderUtils {
	INSTANCE;

	public AddressSetView quantize(int blockBits, AddressSetView set) {
		if (blockBits == 1) {
			return set;
		}
		long blockMask = -1L << blockBits;
		AddressSet result = new AddressSet();
		// Not terribly efficient, but this is one range most of the time
		for (AddressRange range : set) {
			AddressSpace space = range.getAddressSpace();
			Address min = space.getAddress(range.getMinAddress().getOffset() & blockMask);
			Address max = space.getAddress(range.getMaxAddress().getOffset() | ~blockMask);
			result.add(new AddressRangeImpl(min, max));
		}
		return result;
	}

	public CompletableFuture<Void> readMemoryBlocks(
			TraceRecorder recorder, int blockBits, AddressSetView set, TaskMonitor monitor) {

		// NOTE: I don't intend to warn about the number of requests.
		//   They're delivered in serial, and there's a cancel button that works

		int blockSize = 1 << blockBits;
		int total = 0;
		AddressSetView expSet = quantize(blockBits, set);
		for (AddressRange r : expSet) {
			total += Long.divideUnsigned(r.getLength() + blockSize - 1, blockSize);
		}
		monitor.initialize(total);
		monitor.setMessage("Reading memory");
		// TODO: Read blocks in parallel? Probably NO. Tends to overload the connector.
		return AsyncUtils.each(TypeSpec.VOID, expSet.iterator(), (r, loop) -> {
			AddressRangeChunker blocks = new AddressRangeChunker(r, blockSize);
			AsyncUtils.each(TypeSpec.VOID, blocks.iterator(), (blk, inner) -> {
				// The listener in the recorder will copy to the Trace.
				monitor.incrementProgress(1);
				CompletableFuture<byte[]> future =
					recorder.readMemory(blk.getMinAddress(), (int) blk.getLength());
				future.exceptionally(e -> {
					Msg.error(this, "Could not read " + blk + ": " + e);
					return null; // Continue looping on errors
				}).thenApply(__ -> !monitor.isCancelled()).handle(inner::repeatWhile);
			}).thenApply(v -> !monitor.isCancelled()).handle(loop::repeatWhile);
		});
	}
}
