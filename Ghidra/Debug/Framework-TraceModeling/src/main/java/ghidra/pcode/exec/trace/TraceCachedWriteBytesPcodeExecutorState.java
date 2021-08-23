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
package ghidra.pcode.exec.trace;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.*;
import com.google.common.primitives.UnsignedLong;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.AbstractLongOffsetPcodeExecutorState;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.trace.TraceCachedWriteBytesPcodeExecutorState.CachedSpace;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.MemBufferAdapter;
import ghidra.util.MathUtilities;

/**
 * A state which reads bytes from a trace, but caches writes internally.
 * 
 * <p>
 * This provides for "read-only" emulation on a trace. Writes do not affect the source trace, but
 * rather are cached in this state. If desired, those cached writes can be written back out at a
 * later time.
 */
public class TraceCachedWriteBytesPcodeExecutorState
		extends AbstractLongOffsetPcodeExecutorState<byte[], CachedSpace> {

	protected class StateMemBuffer implements MemBufferAdapter {
		protected final Address address;
		protected final CachedSpace source;

		public StateMemBuffer(Address address, CachedSpace source) {
			this.address = address;
			this.source = source;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		@Override
		public Memory getMemory() {
			return null;
		}

		@Override
		public boolean isBigEndian() {
			return trace.getBaseLanguage().isBigEndian();
		}

		@Override
		public int getBytes(ByteBuffer buffer, int addressOffset) {
			byte[] data = source.read(address.getOffset() + addressOffset, buffer.remaining());
			buffer.put(data);
			return data.length;
		}
	}

	protected final Map<AddressSpace, CachedSpace> spaces = new HashMap<>();

	protected final Trace trace;
	protected final long snap;
	protected final TraceThread thread;
	protected final int frame;

	public TraceCachedWriteBytesPcodeExecutorState(Trace trace, long snap, TraceThread thread,
			int frame) {
		super(trace.getBaseLanguage(), BytesPcodeArithmetic.forLanguage(trace.getBaseLanguage()));
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;
	}

	protected static class CachedSpace {
		protected final SemisparseByteArray cache = new SemisparseByteArray();
		protected final RangeSet<UnsignedLong> written = TreeRangeSet.create();
		protected final AddressSpace space;
		protected final TraceMemorySpace source;
		protected final long snap;

		public CachedSpace(AddressSpace space, TraceMemorySpace source, long snap) {
			this.space = space;
			this.source = source;
			this.snap = snap;
		}

		public void write(long offset, byte[] val) {
			cache.putData(offset, val);
			UnsignedLong uLoc = UnsignedLong.fromLongBits(offset);
			UnsignedLong uEnd = UnsignedLong.fromLongBits(offset + val.length);
			written.add(Range.closedOpen(uLoc, uEnd));
		}

		public static long lower(Range<UnsignedLong> rng) {
			return rng.lowerBoundType() == BoundType.CLOSED
					? rng.lowerEndpoint().longValue()
					: rng.lowerEndpoint().longValue() + 1;
		}

		public static long upper(Range<UnsignedLong> rng) {
			return rng.upperBoundType() == BoundType.CLOSED
					? rng.upperEndpoint().longValue()
					: rng.upperEndpoint().longValue() - 1;
		}

		protected void readUninitializedFromSource(RangeSet<UnsignedLong> uninitialized) {
			if (!uninitialized.isEmpty()) {
				Range<UnsignedLong> toRead = uninitialized.span();
				assert toRead.hasUpperBound() && toRead.hasLowerBound();
				long lower = lower(toRead);
				long upper = upper(toRead);
				ByteBuffer buf = ByteBuffer.allocate((int) (upper - lower + 1));
				source.getBytes(snap, space.getAddress(lower), buf);
				for (Range<UnsignedLong> rng : uninitialized.asRanges()) {
					long l = lower(rng);
					long u = upper(rng);
					cache.putData(l, buf.array(), (int) (l - lower), (int) (u - l + 1));
				}
			}
		}

		protected byte[] readCached(long offset, int size) {
			byte[] data = new byte[size];
			cache.getData(offset, data);
			return data;
		}

		public byte[] read(long offset, int size) {
			if (source != null) {
				// TODO: Warn or bail when reading UNKNOWN bytes
				// NOTE: Read without regard to gaps
				// NOTE: Cannot write those gaps, though!!!
				readUninitializedFromSource(cache.getUninitialized(offset, offset + size));
			}
			return readCached(offset, size);
		}

		// Must already have started a transaction
		protected void writeDown(Trace trace, long snap, TraceThread thread, int frame) {
			if (space.isUniqueSpace()) {
				return;
			}
			byte[] data = new byte[4096];
			ByteBuffer buf = ByteBuffer.wrap(data);
			TraceMemorySpace mem =
				TraceSleighUtils.getSpaceForExecution(space, trace, thread, frame, true);
			for (Range<UnsignedLong> range : written.asRanges()) {
				assert range.lowerBoundType() == BoundType.CLOSED;
				assert range.upperBoundType() == BoundType.OPEN;
				long lower = range.lowerEndpoint().longValue();
				long fullLen = range.upperEndpoint().longValue() - lower;
				while (fullLen > 0) {
					int len = MathUtilities.unsignedMin(data.length, fullLen);
					cache.getData(lower, data, 0, len);
					buf.position(0);
					buf.limit(len);
					mem.putBytes(snap, space.getAddress(lower), buf);

					lower += len;
					fullLen -= len;
				}
			}
		}
	}

	public Trace getTrace() {
		return trace;
	}

	public long getSnap() {
		return snap;
	}

	public TraceThread getThread() {
		return thread;
	}

	public int getFrame() {
		return frame;
	}

	/**
	 * Write the accumulated writes into the given trace
	 * 
	 * <p>
	 * NOTE: This method requires a transaction to have already been started on the destination
	 * trace.
	 * 
	 * @param trace the trace to modify
	 * @param snap the snap within the trace
	 * @param thread the thread to take register writes
	 * @param frame the frame for register writes
	 */
	public void writeCacheDown(Trace trace, long snap, TraceThread thread, int frame) {
		if (trace.getBaseLanguage() != language) {
			throw new IllegalArgumentException("Destination trace must be same language as source");
		}
		for (CachedSpace cached : spaces.values()) {
			cached.writeDown(trace, snap, thread, frame);
		}
	}

	@Override
	protected long offsetToLong(byte[] offset) {
		return Utils.bytesToLong(offset, offset.length, language.isBigEndian());
	}

	@Override
	public byte[] longToOffset(AddressSpace space, long l) {
		return arithmetic.fromConst(l, space.getPointerSize());
	}

	protected CachedSpace newSpace(AddressSpace space, TraceMemorySpace source, long snap) {
		return new CachedSpace(space, source, snap);
	}

	@Override
	protected CachedSpace getForSpace(AddressSpace space, boolean toWrite) {
		return spaces.computeIfAbsent(space, s -> {
			TraceMemorySpace tms = s.isUniqueSpace() ? null
					: TraceSleighUtils.getSpaceForExecution(s, trace, thread, frame, false);
			return newSpace(s, tms, snap);
		});
	}

	@Override
	protected void setInSpace(CachedSpace space, long offset, int size, byte[] val) {
		assert size == val.length;
		space.write(offset, val);
	}

	@Override
	protected byte[] getFromSpace(CachedSpace space, long offset, int size) {
		byte[] read = space.read(offset, size);
		if (read.length != size) {
			Address addr = space.space.getAddress(offset);
			throw new UnknownStatePcodeExecutionException("Incomplete read (" + read.length +
				" of " + size + " bytes)", language, addr.add(read.length), size - read.length);
		}
		return read;
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		return new StateMemBuffer(address, getForSpace(address.getAddressSpace(), false));
	}
}
