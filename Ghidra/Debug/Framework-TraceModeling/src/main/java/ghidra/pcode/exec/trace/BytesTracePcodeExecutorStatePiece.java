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

import com.google.common.collect.*;
import com.google.common.primitives.UnsignedLong;

import ghidra.pcode.exec.AbstractBytesPcodeExecutorStatePiece;
import ghidra.pcode.exec.BytesPcodeExecutorStateSpace;
import ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece.CachedSpace;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;

/**
 * A state piece which reads bytes from a trace, but caches writes internally.
 * 
 * <p>
 * This provides for "read-only" emulation on a trace. Writes do not affect the source trace, but
 * rather are cached in this state. If desired, those cached writes can be written back out at a
 * later time.
 */
public class BytesTracePcodeExecutorStatePiece
		extends AbstractBytesPcodeExecutorStatePiece<CachedSpace>
		implements TracePcodeExecutorStatePiece<byte[], byte[]> {

	protected final Trace trace;
	protected final long snap;
	protected final TraceThread thread;
	protected final int frame;

	public BytesTracePcodeExecutorStatePiece(Trace trace, long snap, TraceThread thread,
			int frame) {
		super(trace.getBaseLanguage());
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;
	}

	protected static class CachedSpace extends BytesPcodeExecutorStateSpace<TraceMemorySpace> {
		protected final RangeSet<UnsignedLong> written = TreeRangeSet.create();
		protected final long snap;

		public CachedSpace(Language language, AddressSpace space, TraceMemorySpace backing,
				long snap) {
			super(language, space, backing);
			this.snap = snap;
		}

		@Override
		public void write(long offset, byte[] val, int srcOffset, int length) {
			super.write(offset, val, srcOffset, length);
			UnsignedLong uLoc = UnsignedLong.fromLongBits(offset);
			UnsignedLong uEnd = UnsignedLong.fromLongBits(offset + length);
			written.add(Range.closedOpen(uLoc, uEnd));
		}

		@Override
		protected void readUninitializedFromBacking(RangeSet<UnsignedLong> uninitialized) {
			if (!uninitialized.isEmpty()) {
				// TODO: Warn or bail when reading UNKNOWN bytes
				// NOTE: Read without regard to gaps
				// NOTE: Cannot write those gaps, though!!!
				Range<UnsignedLong> toRead = uninitialized.span();
				assert toRead.hasUpperBound() && toRead.hasLowerBound();
				long lower = lower(toRead);
				long upper = upper(toRead);
				ByteBuffer buf = ByteBuffer.allocate((int) (upper - lower + 1));
				backing.getBytes(snap, space.getAddress(lower), buf);
				for (Range<UnsignedLong> rng : uninitialized.asRanges()) {
					long l = lower(rng);
					long u = upper(rng);
					bytes.putData(l, buf.array(), (int) (l - lower), (int) (u - l + 1));
				}
			}
		}

		protected void warnUnknown(AddressSet unknown) {
			warnAddressSet("Emulator state initialized from UNKNOWN", unknown);
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
					bytes.getData(lower, data, 0, len);
					buf.position(0);
					buf.limit(len);
					mem.putBytes(snap, space.getAddress(lower), buf);

					lower += len;
					fullLen -= len;
				}
			}
		}
	}

	/**
	 * Get the state's source trace
	 * 
	 * @return the trace
	 */
	public Trace getTrace() {
		return trace;
	}

	/**
	 * Get the source snap
	 * 
	 * @return the snap
	 */
	public long getSnap() {
		return snap;
	}

	/**
	 * Get the source thread, if a local state
	 * 
	 * @return the thread
	 */
	public TraceThread getThread() {
		return thread;
	}

	/**
	 * Get the source frame, if a local state
	 * 
	 * @return the frame, probably 0
	 */
	public int getFrame() {
		return frame;
	}

	@Override
	public void writeDown(Trace trace, long snap, TraceThread thread, int frame) {
		if (trace.getBaseLanguage() != language) {
			throw new IllegalArgumentException("Destination trace must be same language as source");
		}
		for (CachedSpace cached : spaceMap.values()) {
			cached.writeDown(trace, snap, thread, frame);
		}
	}

	/**
	 * A space map which binds spaces to corresponding spaces in the trace
	 */
	protected class TraceBackedSpaceMap extends CacheingSpaceMap<TraceMemorySpace, CachedSpace> {
		@Override
		protected TraceMemorySpace getBacking(AddressSpace space) {
			return TraceSleighUtils.getSpaceForExecution(space, trace, thread, frame, false);
		}

		@Override
		protected CachedSpace newSpace(AddressSpace space, TraceMemorySpace backing) {
			return new CachedSpace(language, space, backing, snap);
		}
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new TraceBackedSpaceMap();
	}
}
