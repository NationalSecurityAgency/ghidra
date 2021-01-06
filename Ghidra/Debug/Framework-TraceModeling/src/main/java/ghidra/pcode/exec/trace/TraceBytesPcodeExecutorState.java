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

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.DefaultTraceTimeViewport;

public class TraceBytesPcodeExecutorState
		extends AbstractLongOffsetPcodeExecutorState<byte[], TraceMemorySpace> {

	protected final SemisparseByteArray unique = new SemisparseByteArray();
	private final Trace trace;
	private long snap;
	private TraceThread thread;
	private int frame;

	private final DefaultTraceTimeViewport viewport;

	public TraceBytesPcodeExecutorState(Trace trace, long snap, TraceThread thread, int frame) {
		super(trace.getBaseLanguage(), BytesPcodeArithmetic.forLanguage(trace.getBaseLanguage()));
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;

		this.viewport = new DefaultTraceTimeViewport(trace);
		this.viewport.setSnap(snap);
	}

	public PcodeExecutorState<Pair<byte[], TraceMemoryState>> withMemoryState() {
		return new PairedPcodeExecutorState<>(this,
			new TraceMemoryStatePcodeExecutorStatePiece(trace, snap, thread, frame)) {

			@Override
			public void setVar(AddressSpace space, Pair<byte[], TraceMemoryState> offset, int size,
					boolean truncateAddressableUnit, Pair<byte[], TraceMemoryState> val) {
				if (offset.getRight() == TraceMemoryState.KNOWN) {
					super.setVar(space, offset, size, truncateAddressableUnit, val);
					return;
				}
				super.setVar(space, offset, size, truncateAddressableUnit,
					new ImmutablePair<>(val.getLeft(), TraceMemoryState.UNKNOWN));
			}

			@Override
			public Pair<byte[], TraceMemoryState> getVar(AddressSpace space,
					Pair<byte[], TraceMemoryState> offset, int size,
					boolean truncateAddressableUnit) {
				Pair<byte[], TraceMemoryState> result =
					super.getVar(space, offset, size, truncateAddressableUnit);
				if (offset.getRight() == TraceMemoryState.KNOWN) {
					return result;
				}
				return new ImmutablePair<>(result.getLeft(), TraceMemoryState.UNKNOWN);
			}
		};
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

	@Override
	public long offsetToLong(byte[] offset) {
		return Utils.bytesToLong(offset, offset.length, language.isBigEndian());
	}

	@Override
	public byte[] longToOffset(AddressSpace space, long l) {
		return arithmetic.fromConst(l, space.getPointerSize());
	}

	@Override
	protected void setUnique(long offset, int size, byte[] val) {
		assert size == val.length;
		unique.putData(offset, val);
	}

	@Override
	protected byte[] getUnique(long offset, int size) {
		byte[] data = new byte[size];
		unique.getData(offset, data);
		return data;
	}

	@Override
	protected TraceMemorySpace getForSpace(AddressSpace space, boolean toWrite) {
		return TraceSleighUtils.getSpaceForExecution(space, trace, thread, frame, toWrite);
	}

	@Override
	protected void setInSpace(TraceMemorySpace space, long offset, int size, byte[] val) {
		assert size == val.length;
		int wrote =
			space.putBytes(snap, space.getAddressSpace().getAddress(offset), ByteBuffer.wrap(val));
		if (wrote != size) {
			throw new RuntimeException("Could not write full value to trace");
		}
	}

	@Override
	protected byte[] getFromSpace(TraceMemorySpace space, long offset, int size) {
		ByteBuffer buf = ByteBuffer.allocate(size);
		int read = space.getViewBytes(snap, space.getAddressSpace().getAddress(offset), buf);
		if (read != size) {
			throw new RuntimeException("Could not read full value from trace");
		}
		return buf.array();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		return trace.getMemoryManager().getBufferAt(snap, address);
	}
}
