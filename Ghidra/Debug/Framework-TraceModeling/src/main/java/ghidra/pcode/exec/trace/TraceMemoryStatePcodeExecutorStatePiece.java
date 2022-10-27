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

import java.util.Map.Entry;

import generic.ULongSpan;
import generic.ULongSpan.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * The p-code execute state piece for {@link TraceMemoryState}
 *
 * <p>
 * This state piece is meant to be used as an auxiliary to a concrete trace-bound state. See
 * {@link DirectBytesTracePcodeExecutorState#withMemoryState()}. It should be used with
 * {@link TraceMemoryStatePcodeArithmetic} as a means of computing the "state" of a Sleigh
 * expression's value. It essentially works like a rudimentary taint analyzer: If any part of any
 * input to the expression in tainted, i.e., not {@link TraceMemoryState#KNOWN}, then the result is
 * {@link TraceMemoryState#UNKNOWN}. This is best exemplified in {@link #getUnique(long, int)},
 * though it's also exemplified in {@link #getFromSpace(TraceMemorySpace, long, int)}.
 */
public class TraceMemoryStatePcodeExecutorStatePiece extends
		AbstractLongOffsetPcodeExecutorStatePiece<byte[], TraceMemoryState, AddressSpace> {

	protected final MutableULongSpanMap<TraceMemoryState> unique = new DefaultULongSpanMap<>();
	protected final PcodeTraceDataAccess data;

	/**
	 * Construct a piece
	 * 
	 * @param data the trace-data access shim
	 */
	public TraceMemoryStatePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data.getLanguage(),
			BytesPcodeArithmetic.forLanguage(data.getLanguage()),
			TraceMemoryStatePcodeArithmetic.INSTANCE);
		this.data = data;
	}

	protected AddressRange range(AddressSpace space, long offset, int size) {
		try {
			return new AddressRangeImpl(space.getAddress(offset), size);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void setUnique(long offset, int size, TraceMemoryState val) {
		unique.put(ULongSpan.extent(offset, size), val);
	}

	@Override
	protected TraceMemoryState getUnique(long offset, int size, Reason reason) {
		MutableULongSpanSet remains = new DefaultULongSpanSet();
		ULongSpan span = ULongSpan.extent(offset, size);
		remains.add(span);
		for (Entry<ULongSpan, TraceMemoryState> ent : unique.intersectingEntries(span)) {
			if (ent.getValue() != TraceMemoryState.KNOWN) {
				return TraceMemoryState.UNKNOWN;
			}
			remains.remove(ent.getKey());
		}
		return remains.isEmpty() ? TraceMemoryState.KNOWN : TraceMemoryState.UNKNOWN;
	}

	@Override
	protected AddressSpace getForSpace(AddressSpace space, boolean toWrite) {
		return space;
	}

	@Override
	protected void setInSpace(AddressSpace space, long offset, int size, TraceMemoryState val) {
		// NB. Will ensure writes with unknown state are still marked unknown
		data.setState(range(space, offset, size), val);
	}

	@Override
	protected TraceMemoryState getFromSpace(AddressSpace space, long offset, int size,
			Reason reason) {
		return data.getViewportState(range(space, offset, size));
	}

	@Override
	protected TraceMemoryState getFromNullSpace(int size, Reason reason) {
		return TraceMemoryState.UNKNOWN;
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new ConcretionError("Cannot make TraceMemoryState into a concrete buffer", purpose);
	}

	@Override
	public void clear() {
		unique.clear();
	}
}
