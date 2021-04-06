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

import java.util.Map;

import com.google.common.collect.*;
import com.google.common.primitives.UnsignedLong;

import ghidra.pcode.exec.AbstractLongOffsetPcodeExecutorStatePiece;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.DefaultTraceTimeViewport;

public class TraceMemoryStatePcodeExecutorStatePiece extends
		AbstractLongOffsetPcodeExecutorStatePiece<byte[], TraceMemoryState, TraceMemorySpace> {

	private final RangeMap<UnsignedLong, TraceMemoryState> unique = TreeRangeMap.create();
	private final Trace trace;
	private long snap;
	private TraceThread thread;
	private int frame;

	private final DefaultTraceTimeViewport viewport;

	public TraceMemoryStatePcodeExecutorStatePiece(Trace trace, long snap, TraceThread thread,
			int frame) {
		super(trace.getBaseLanguage(), TraceMemoryStatePcodeArithmetic.INSTANCE);
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;

		this.viewport = new DefaultTraceTimeViewport(trace);
		this.viewport.setSnap(snap);
	}

	public Trace getTrace() {
		return trace;
	}

	public void setSnap(long snap) {
		this.snap = snap;
		this.viewport.setSnap(snap);
	}

	public long getSnap() {
		return snap;
	}

	public void setThread(TraceThread thread) {
		if (thread != null & thread.getTrace() != trace) {
			throw new IllegalArgumentException("Thread, if given, must be part of the same trace");
		}
		this.thread = thread;
	}

	public TraceThread getThread() {
		return thread;
	}

	public void setFrame(int frame) {
		this.frame = frame;
	}

	public int getFrame() {
		return frame;
	}

	protected Range<UnsignedLong> range(long offset, int size) {
		return Range.closedOpen(UnsignedLong.fromLongBits(offset),
			UnsignedLong.fromLongBits(offset + size));
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
	protected long offsetToLong(byte[] offset) {
		return Utils.bytesToLong(offset, offset.length, language.isBigEndian());
	}

	@Override
	public byte[] longToOffset(AddressSpace space, long l) {
		return Utils.longToBytes(l, space.getPointerSize(), language.isBigEndian());
	}

	@Override
	protected void setUnique(long offset, int size, TraceMemoryState val) {
		unique.put(range(offset, size), val);
	}

	@Override
	protected TraceMemoryState getUnique(long offset, int size) {
		RangeSet<UnsignedLong> remains = TreeRangeSet.create();
		Range<UnsignedLong> range = range(offset, size);
		remains.add(range);

		for (Map.Entry<Range<UnsignedLong>, TraceMemoryState> ent : unique.subRangeMap(range)
				.asMapOfRanges()
				.entrySet()) {
			if (ent.getValue() != TraceMemoryState.KNOWN) {
				return TraceMemoryState.UNKNOWN;
			}
			remains.remove(ent.getKey());
		}
		return remains.isEmpty() ? TraceMemoryState.KNOWN : TraceMemoryState.UNKNOWN;
	}

	@Override
	protected TraceMemorySpace getForSpace(AddressSpace space, boolean toWrite) {
		return TraceSleighUtils.getSpaceForExecution(space, trace, thread, frame, toWrite);
	}

	@Override
	protected void setInSpace(TraceMemorySpace space, long offset, int size, TraceMemoryState val) {
		// NB. Will ensure writes with unknown state are still marked unknown
		space.setState(size, space.getAddressSpace().getAddress(offset), val);
	}

	@Override
	protected TraceMemoryState getFromSpace(TraceMemorySpace space, long offset, int size) {
		AddressSet set = new AddressSet(range(space.getAddressSpace(), offset, size));
		for (long snap : viewport.getOrderedSnaps()) {
			set.delete(
				space.getAddressesWithState(snap, set, state -> state == TraceMemoryState.KNOWN));
		}
		return set.isEmpty() ? TraceMemoryState.KNOWN : TraceMemoryState.UNKNOWN;
	}

	@Override
	protected TraceMemoryState getFromNullSpace(int size) {
		return TraceMemoryState.UNKNOWN;
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		throw new AssertionError("Cannot make TraceMemoryState into a concrete buffer");
	}
}
