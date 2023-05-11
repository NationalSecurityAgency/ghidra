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
import java.util.Map;

import generic.ULongSpan;
import generic.ULongSpan.ULongSpanSet;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.AbstractBytesPcodeExecutorStatePiece;
import ghidra.pcode.exec.BytesPcodeExecutorStateSpace;
import ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece.CachedSpace;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
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

	protected static class CachedSpace
			extends BytesPcodeExecutorStateSpace<PcodeTraceDataAccess> {
		protected final AddressSet written;

		public CachedSpace(Language language, AddressSpace space, PcodeTraceDataAccess backing) {
			// Backing could be null, so we need language parameter
			super(language, space, backing);
			this.written = new AddressSet();
		}

		protected CachedSpace(Language language, AddressSpace space, PcodeTraceDataAccess backing,
				SemisparseByteArray bytes, AddressSet written) {
			super(language, space, backing, bytes);
			this.written = written;
		}

		@Override
		public CachedSpace fork() {
			return new CachedSpace(language, space, backing, bytes.fork(), new AddressSet(written));
		}

		@Override
		public void write(long offset, byte[] val, int srcOffset, int length) {
			super.write(offset, val, srcOffset, length);
			Address loc = space.getAddress(offset);
			Address end = loc.addWrap(length - 1);
			if (loc.compareTo(end) <= 0) {
				written.add(loc, end);
			}
			else {
				written.add(loc, space.getMaxAddress());
				written.add(space.getMinAddress(), end);
			}
		}

		protected AddressSetView intersectViewKnown(AddressSetView set) {
			return backing.intersectViewKnown(set, true);
		}

		@Override
		protected ULongSpanSet readUninitializedFromBacking(ULongSpanSet uninitialized) {
			if (uninitialized.isEmpty()) {
				return uninitialized;
			}
			// TODO: Warn or bail when reading UNKNOWN bytes
			// NOTE: Read without regard to gaps
			// NOTE: Cannot write those gaps, though!!!
			AddressSetView knownButUninit = intersectViewKnown(addrSet(uninitialized));
			if (knownButUninit.isEmpty()) {
				return uninitialized;
			}
			AddressRange knownBound = new AddressRangeImpl(
				knownButUninit.getMinAddress(),
				knownButUninit.getMaxAddress());
			ByteBuffer buf = ByteBuffer.allocate((int) knownBound.getLength());
			backing.getBytes(knownBound.getMinAddress(), buf);
			for (AddressRange range : knownButUninit) {
				bytes.putData(range.getMinAddress().getOffset(), buf.array(),
					(int) (range.getMinAddress().subtract(knownBound.getMinAddress())),
					(int) range.getLength());
			}
			ULongSpan uninitBound = uninitialized.bound();
			return bytes.getUninitialized(uninitBound.min(), uninitBound.max());
		}

		protected void warnUnknown(AddressSetView unknown) {
			warnAddressSet("Emulator state initialized from UNKNOWN", unknown);
		}

		// Must already have started a transaction
		protected void writeDown(PcodeTraceDataAccess into) {
			if (space.isUniqueSpace()) {
				return;
			}
			byte[] data = new byte[4096];
			ByteBuffer buf = ByteBuffer.wrap(data);
			for (AddressRange range : written) {
				long lower = range.getMinAddress().getOffset();
				long fullLen = range.getLength();
				while (fullLen > 0) {
					int len = MathUtilities.unsignedMin(data.length, fullLen);
					bytes.getData(lower, data, 0, len);
					buf.position(0);
					buf.limit(len);
					into.putBytes(space.getAddress(lower), buf);

					lower += len;
					fullLen -= len;
				}
			}
		}
	}

	protected final PcodeTraceDataAccess data;

	/**
	 * Create a concrete state piece backed by a trace
	 * 
	 * @param data the trace-data access shim
	 */
	public BytesTracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data.getLanguage());
		this.data = data;
	}

	protected BytesTracePcodeExecutorStatePiece(PcodeTraceDataAccess data,
			AbstractSpaceMap<CachedSpace> spaceMap) {
		super(data.getLanguage(), spaceMap);
		this.data = data;
	}

	@Override
	public PcodeTraceDataAccess getData() {
		return data;
	}

	@Override
	public BytesTracePcodeExecutorStatePiece fork() {
		return new BytesTracePcodeExecutorStatePiece(data, spaceMap.fork());
	}

	@Override
	public void writeDown(PcodeTraceDataAccess into) {
		if (into.getLanguage() != language) {
			throw new IllegalArgumentException(
				"Destination platform must be same language as source");
		}
		for (CachedSpace cached : spaceMap.values()) {
			cached.writeDown(into);
		}
	}

	/**
	 * A space map which binds spaces to corresponding spaces in the trace
	 */
	protected class TraceBackedSpaceMap
			extends CacheingSpaceMap<PcodeTraceDataAccess, CachedSpace> {
		public TraceBackedSpaceMap() {
			super();
		}

		protected TraceBackedSpaceMap(Map<AddressSpace, CachedSpace> spaces) {
			super(spaces);
		}

		@Override
		protected PcodeTraceDataAccess getBacking(AddressSpace space) {
			return data;
		}

		@Override
		protected CachedSpace newSpace(AddressSpace space, PcodeTraceDataAccess backing) {
			return new CachedSpace(language, space, backing);
		}

		@Override
		public TraceBackedSpaceMap fork() {
			return new TraceBackedSpaceMap(fork(spaces));
		}

		@Override
		public CachedSpace fork(CachedSpace s) {
			return s.fork();
		}
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new TraceBackedSpaceMap();
	}
}
