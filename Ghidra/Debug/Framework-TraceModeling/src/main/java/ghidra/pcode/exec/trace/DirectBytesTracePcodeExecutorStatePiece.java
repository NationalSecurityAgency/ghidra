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

import org.apache.commons.lang3.tuple.Pair;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.DefaultTraceTimeViewport;

/**
 * An executor state piece that operates directly on trace memory and registers
 * 
 * <p>
 * This differs from {@link BytesTracePcodeExecutorStatePiece} in that writes performed by the
 * emulator immediately affect the trace. There is no caching. In effect, the trace <em>is</em> the
 * state. This is used primarily in testing to initialize trace state using Sleigh, which is more
 * succinct than accessing trace memory and registers via the trace API. It may also be incorporated
 * into the UI at a later time.
 * 
 * @see TraceSleighUtils
 */
public class DirectBytesTracePcodeExecutorStatePiece
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], byte[], TraceMemorySpace> {

	protected final SemisparseByteArray unique = new SemisparseByteArray();
	private final Trace trace;
	private long snap;
	private TraceThread thread;
	private int frame;

	private final DefaultTraceTimeViewport viewport;

	protected DirectBytesTracePcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> arithmetic, Trace trace, long snap, TraceThread thread,
			int frame) {
		super(language, arithmetic, arithmetic);
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;

		this.viewport = new DefaultTraceTimeViewport(trace);
		this.viewport.setSnap(snap);
	}

	protected DirectBytesTracePcodeExecutorStatePiece(Language language, Trace trace, long snap,
			TraceThread thread, int frame) {
		this(language, BytesPcodeArithmetic.forLanguage(language), trace, snap, thread, frame);
	}

	public DirectBytesTracePcodeExecutorStatePiece(Trace trace, long snap, TraceThread thread,
			int frame) {
		this(trace.getBaseLanguage(), trace, snap, thread, frame);
	}

	/**
	 * Create a state which computes an expression's {@link TraceMemoryState} as an auxiliary
	 * attribute
	 * 
	 * <p>
	 * If every part of every input to the expression is {@link TraceMemoryState#KNOWN}, then the
	 * expression's value will be marked {@link TraceMemoryState#KNOWN}. Otherwise, it's marked
	 * {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * @return the paired executor state
	 */
	public PcodeExecutorStatePiece<byte[], Pair<byte[], TraceMemoryState>> withMemoryState() {
		return new PairedPcodeExecutorStatePiece<>(this,
			new TraceMemoryStatePcodeExecutorStatePiece(trace, snap, thread, frame));
	}

	/**
	 * Get the trace
	 * 
	 * @return the trace
	 */
	public Trace getTrace() {
		return trace;
	}

	/**
	 * Re-bind this state to another snap
	 * 
	 * @param snap the new snap
	 */
	public void setSnap(long snap) {
		this.snap = snap;
		this.viewport.setSnap(snap);
	}

	/**
	 * Get the current snap
	 * 
	 * @return the snap
	 */
	public long getSnap() {
		return snap;
	}

	/**
	 * Re-bind this state to another thread
	 * 
	 * @param thread the new thread
	 */
	public void setThread(TraceThread thread) {
		if (thread != null & thread.getTrace() != trace) {
			throw new IllegalArgumentException("Thread, if given, must be part of the same trace");
		}
		this.thread = thread;
	}

	/**
	 * Get the current thread
	 * 
	 * @return the thread
	 */
	public TraceThread getThread() {
		return thread;
	}

	/**
	 * Re-bind this state to another frame
	 * 
	 * @param frame the new frame
	 */
	public void setFrame(int frame) {
		this.frame = frame;
	}

	/**
	 * Get the current frame
	 * 
	 * @return the frame
	 */
	public int getFrame() {
		return frame;
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
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		return trace.getMemoryManager().getBufferAt(snap, address);
	}
}
