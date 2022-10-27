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

import generic.ULongSpan.ULongSpanSet;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;

/**
 * A state piece which can check for uninitialized reads
 * 
 * <p>
 * Depending on the use case, it may be desirable to ensure all reads through the course of
 * emulation are from initialized parts of memory. For traces, there's an additional consideration
 * as to whether the values are present, but stale. Again, depending on the use case, that may be
 * acceptable. See the extensions of this class for "stock" implementations.
 */
public abstract class AbstractCheckedTraceCachedWriteBytesPcodeExecutorStatePiece
		extends BytesTracePcodeExecutorStatePiece {

	protected class CheckedCachedSpace extends CachedSpace {
		public CheckedCachedSpace(Language language, AddressSpace space,
				PcodeTraceDataAccess backing) {
			super(language, space, backing);
		}

		@Override
		public byte[] read(long offset, int size, Reason reason) {
			ULongSpanSet uninitialized =
				bytes.getUninitialized(offset, offset + size - 1);
			if (!uninitialized.isEmpty()) {
				size = checkUninitialized(backing, space.getAddress(offset), size,
					addrSet(uninitialized));
			}
			return super.read(offset, size, reason);
		}
	}

	/**
	 * Construct a piece
	 * 
	 * @param data the trace-data access shim
	 */
	public AbstractCheckedTraceCachedWriteBytesPcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data);
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new TraceBackedSpaceMap() {
			@Override
			protected CachedSpace newSpace(AddressSpace space, PcodeTraceDataAccess backing) {
				return new CheckedCachedSpace(language, space, backing);
			}
		};
	}

	/**
	 * Decide what to do, given that a portion of a read is uninitialized
	 * 
	 * @param backing the shim backing the address space that was read
	 * @param start the starting address of the requested read
	 * @param size the size of the requested read
	 * @param uninitialized the portion of the read that is uninitialized
	 * @return the adjusted size of the read
	 * @throws Exception to interrupt the emulator
	 */
	protected abstract int checkUninitialized(PcodeTraceDataAccess backing, Address start,
			int size, AddressSet uninitialized);
}
