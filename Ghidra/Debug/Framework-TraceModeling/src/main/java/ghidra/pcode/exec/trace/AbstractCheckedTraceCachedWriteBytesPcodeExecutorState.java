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

import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;
import com.google.common.primitives.UnsignedLong;

import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;

public abstract class AbstractCheckedTraceCachedWriteBytesPcodeExecutorState
		extends TraceCachedWriteBytesPcodeExecutorState {

	protected class CheckedCachedSpace extends CachedSpace {
		public CheckedCachedSpace(AddressSpace space, TraceMemorySpace source, long snap) {
			super(space, source, snap);
		}

		protected AddressRange addrRng(Range<UnsignedLong> rng) {
			Address start = space.getAddress(lower(rng));
			Address end = space.getAddress(upper(rng));
			return new AddressRangeImpl(start, end);
		}

		protected AddressSet addrSet(RangeSet<UnsignedLong> set) {
			AddressSet result = new AddressSet();
			for (Range<UnsignedLong> rng : set.asRanges()) {
				result.add(addrRng(rng));
			}
			return result;
		}

		@Override
		public byte[] read(long offset, int size) {
			RangeSet<UnsignedLong> uninitialized = cache.getUninitialized(offset, offset + size);

			if (!uninitialized.isEmpty()) {
				size = checkUninitialized(source, space.getAddress(offset), size,
					addrSet(uninitialized));
				if (source != null) {
					readUninitializedFromSource(uninitialized);
				}
			}
			return readCached(offset, size);
		}
	}

	public AbstractCheckedTraceCachedWriteBytesPcodeExecutorState(Trace trace, long snap,
			TraceThread thread, int frame) {
		super(trace, snap, thread, frame);
	}

	@Override
	protected CachedSpace newSpace(AddressSpace space, TraceMemorySpace source, long snap) {
		return new CheckedCachedSpace(space, source, snap);
	}

	protected abstract int checkUninitialized(TraceMemorySpace source, Address start, int size,
			AddressSet uninitialized);
}
