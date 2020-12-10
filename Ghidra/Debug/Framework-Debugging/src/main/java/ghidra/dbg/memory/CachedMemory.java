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
package ghidra.dbg.memory;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.collect.*;
import com.google.common.primitives.UnsignedLong;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetThread;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.util.Msg;

/**
 * A cached memory wrapper
 * 
 * Because debugging channels can be slow, memory reads and writes ought to be cached for the
 * duration a thread (and threads sharing the same memory) are stopped. This highly-recommended
 * convenience implements a write-through single-layer cache. The implementor need only provide
 * references to the basic asynchronous read/write methods. Those are usually private methods of the
 * {@link TargetThread} or {@link TargetProcess} implementation. The public read/write methods just
 * wrap the read/write methods provided by this cache.
 * 
 * Implementation note: The cache is backed by a {@link SemisparseByteArray}, which is well-suited
 * for reads and writes within a locality. Nothing is evicted from the cache automatically. All
 * eviction is done manually by a call to {@link #clear()}. During a debug session, there are
 * typically few reads or writes between execution steps. Given the purpose is to eliminate
 * unnecessary reads, there is little motivation to implement an automatic eviction strategy. The
 * debugger client implementation must clear the cache at each execution step, unless it can
 * accurately determine that certain ranges of memory cannot be affected by a given step.
 */
public class CachedMemory implements MemoryReader, MemoryWriter {
	private final SemisparseByteArray memory = new SemisparseByteArray();
	private final NavigableMap<UnsignedLong, PendingRead> pendingByLoc = new TreeMap<>();
	private final MemoryReader reader;
	private final MemoryWriter writer;

	protected static class PendingRead {
		final Range<UnsignedLong> range;
		final CompletableFuture<Void> future;

		protected PendingRead(Range<UnsignedLong> range, CompletableFuture<Void> future) {
			this.range = range;
			this.future = future;
		}
	}

	/**
	 * Create a new cache wrapping the given read/write methods
	 * 
	 * The wrapped read/write methods are usually private
	 * 
	 * @param reader the read implementation, usually a method reference
	 * @param writer the write implementation, usually a method reference
	 */
	public CachedMemory(MemoryReader reader, MemoryWriter writer) {
		this.reader = reader;
		this.writer = writer;
	}

	@Override
	public CompletableFuture<Void> writeMemory(long addr, byte[] data) {
		// TODO: Do I write to the cache first, and correct if an error occurs?
		// Or leave it as write to cache on known success
		return writer.writeMemory(addr, data).thenAccept(__ -> {
			memory.putData(addr, data);
		});
	}

	protected synchronized CompletableFuture<Void> waitForReads(long addr, int len) {
		RangeSet<UnsignedLong> undefined = memory.getUninitialized(addr, addr + len);
		// Do the reads in parallel
		AsyncFence fence = new AsyncFence();
		for (Range<UnsignedLong> rng : undefined.asRanges()) {
			findPendingOrSchedule(rng, fence);
		}
		return fence.ready();
	}

	protected synchronized void findPendingOrSchedule(final Range<UnsignedLong> rng,
			final AsyncFence fence) {
		RangeSet<UnsignedLong> needRequests = TreeRangeSet.create();
		needRequests.add(rng);

		// Find all existing requests and include them in the fence
		// Check if there is a preceding range which overlaps the desired range:
		Entry<UnsignedLong, PendingRead> prec = pendingByLoc.lowerEntry(rng.lowerEndpoint());
		if (prec != null) {
			PendingRead pending = prec.getValue();
			if (!pending.future.isCompletedExceptionally() && rng.isConnected(pending.range)) {
				needRequests.remove(pending.range);
				fence.include(pending.future);
			}
		}
		NavigableMap<UnsignedLong, PendingRead> applicablePending =
			pendingByLoc.subMap(rng.lowerEndpoint(), true, rng.upperEndpoint(), false);
		for (Map.Entry<UnsignedLong, PendingRead> ent : applicablePending.entrySet()) {
			PendingRead pending = ent.getValue();
			if (pending.future.isCompletedExceptionally()) {
				continue;
			}
			needRequests.remove(pending.range);
			fence.include(pending.future);
		}

		// Now we're left with a set of needed ranges. Make a request for each
		for (Range<UnsignedLong> needed : needRequests.asRanges()) {
			final UnsignedLong lower = needed.lowerEndpoint();
			final UnsignedLong upper = needed.upperEndpoint();
			/*Msg.debug(this,
				"Need to read: [" + lower.toString(16) + ":" + upper.toString(16) + ")");*/
			CompletableFuture<byte[]> futureRead =
				reader.readMemory(lower.longValue(), upper.minus(lower).intValue());
			// Async to avoid re-entrant lock problem
			CompletableFuture<Void> futureStored = futureRead.thenAcceptAsync(data -> {
				synchronized (this) {
					/*Msg.debug(this, "Completed read at " + lower.toString(16) + ": " +
						NumericUtilities.convertBytesToString(data));*/
					if (pendingByLoc.remove(lower) != null) {
						/**
						 * If the cache was cleared while this read was still pending, we do not
						 * want to record the result.
						 */
						memory.putData(lower.longValue(), data);
						//Msg.debug(this, "Cached read at " + lower.toString(16));
					}
				}
			}).exceptionally(e -> {
				Msg.error(this, "Unexpected error caching memory: ", e);
				synchronized (this) {
					pendingByLoc.remove(lower);
				}
				return ExceptionUtils.rethrow(e);
			});
			pendingByLoc.put(lower, new PendingRead(rng, futureStored));
			fence.include(futureStored);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote In some circumstances, it may actually be less efficient to split a request,
	 *           especially if the split only saves a few bytes. The logic required to efficiently
	 *           handle those circumstances would require a bit of calibration based on empirical
	 *           measures, so until such a change becomes necessary, the naive splitting logic
	 *           remains.
	 */
	@Override
	public CompletableFuture<byte[]> readMemory(long addr, int len) {
		AssertionError defaultErr =
			new AssertionError("No data available even after a successful read?");
		AtomicReference<Throwable> exc = new AtomicReference<>(defaultErr);
		//Msg.debug(this, "Reading " + len + " bytes at " + Long.toUnsignedString(addr, 16));
		return waitForReads(addr, len).handle((v, e) -> {
			int available = memory.contiguousAvailableAfter(addr);
			if (available == 0) {
				if (e == null) {
					// TODO: This is happening. Fix it!
					throw new AssertionError("No data available at " +
						Long.toUnsignedString(addr, 16) + " even after a successful read?");
				}
				else {
					return ExceptionUtils.rethrow(e);
				}
			}
			if (e != null && !isTimeout(e)) {
				Msg.error(this,
					"Some reads requested by the cache failed. Returning a partial result: " +
						exc.get());
			}
			byte[] result = new byte[Math.min(len, available)];
			memory.getData(addr, result);
			return result;
		});
	}

	/**
	 * Update target memory cache by some out-of-band means
	 * 
	 * @param address the offset of the address
	 * @param data the contents to cache
	 */
	public void updateMemory(long address, byte[] data) {
		/*Msg.debug(this, "Memory Cache updated at " + address + ": " +
			NumericUtilities.convertBytesToString(data));*/
		memory.putData(address, data);
	}

	/**
	 * Reset the cache
	 * 
	 * The next read command is guaranteed to be forwarded in its entirety.
	 */
	public void clear() {
		List<PendingRead> toCancel;
		synchronized (this) {
			//Msg.debug(this, "Memory Cache cleared");
			memory.clear();
			toCancel = List.copyOf(pendingByLoc.values());
			pendingByLoc.clear();
		}
		for (PendingRead pendingRead : toCancel) {
			pendingRead.future.cancel(true);
		}
	}

	protected boolean isTimeout(Throwable e) {
		e = AsyncUtils.unwrapThrowable(e);
		if (e instanceof TimeoutException) {
			return true;
		}
		return false;
	}
}
