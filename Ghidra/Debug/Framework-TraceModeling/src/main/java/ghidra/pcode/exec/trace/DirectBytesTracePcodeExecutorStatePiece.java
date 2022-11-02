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

import javax.help.UnsupportedOperationException;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.memory.TraceMemoryState;

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
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], byte[], AddressSpace>
		implements TracePcodeExecutorStatePiece<byte[], byte[]> {

	protected final PcodeTraceDataAccess data;

	protected final SemisparseByteArray unique = new SemisparseByteArray();

	/**
	 * Construct a piece
	 * 
	 * @param arithmetic the arithmetic for byte arrays
	 * @param data the trace-data access shim
	 */
	protected DirectBytesTracePcodeExecutorStatePiece(PcodeArithmetic<byte[]> arithmetic,
			PcodeTraceDataAccess data) {
		super(data.getLanguage(), arithmetic, arithmetic);
		this.data = data;
	}

	/**
	 * Construct a piece
	 * 
	 * @param data the trace-data access shim
	 */
	public DirectBytesTracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		this(BytesPcodeArithmetic.forLanguage(data.getLanguage()), data);
	}

	@Override
	public PcodeTraceDataAccess getData() {
		return data;
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
			new TraceMemoryStatePcodeExecutorStatePiece(data));
	}

	@Override
	protected void setUnique(long offset, int size, byte[] val) {
		assert size == val.length;
		unique.putData(offset, val);
	}

	@Override
	protected byte[] getUnique(long offset, int size, Reason reason) {
		byte[] data = new byte[size];
		unique.getData(offset, data);
		return data;
	}

	@Override
	protected AddressSpace getForSpace(AddressSpace space, boolean toWrite) {
		return space;
	}

	@Override
	protected void setInSpace(AddressSpace space, long offset, int size, byte[] val) {
		assert size == val.length;
		int wrote = data.putBytes(space.getAddress(offset), ByteBuffer.wrap(val));
		if (wrote != size) {
			throw new RuntimeException("Could not write full value to trace");
		}
	}

	@Override
	protected byte[] getFromSpace(AddressSpace space, long offset, int size, Reason reason) {
		ByteBuffer buf = ByteBuffer.allocate(size);
		int read = data.getBytes(space.getAddress(offset), buf);
		if (read != size) {
			throw new RuntimeException("Could not read full value from trace");
		}
		return buf.array();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void writeDown(PcodeTraceDataAccess into) {
		// Writes directly, so just ignore
	}

	@Override
	public void clear() {
		unique.clear();
	}
}
