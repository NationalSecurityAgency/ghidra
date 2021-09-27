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
package ghidra.app.plugin.core.debug.gui.memory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.plugin.core.byteviewer.MemoryByteBlock;
import ghidra.app.plugin.core.format.ByteBlockAccessException;
import ghidra.app.services.TraceRecorder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * An extension of MemoryByteBlock that redirects applicable writes to a debug target
 */
public class WritesTargetMemoryByteBlock extends MemoryByteBlock {
	protected final WritesTargetProgramByteBlockSet blockSet;

	/**
	 * Constructor.
	 * 
	 * @param blockSet the containing block set
	 * @param program the trace program view for the block
	 * @param memory the view's memory
	 * @param block the view's memory block
	 */
	public WritesTargetMemoryByteBlock(WritesTargetProgramByteBlockSet blockSet, Program program,
			Memory memory, MemoryBlock block) {
		super(program, memory, block);
		this.blockSet = blockSet;
	}

	/**
	 * Check writes should be redirected, based on the provider's coordinates.
	 * 
	 * <p>
	 * Note that redirecting the write prevents the edit from being written (dirtectly) into the
	 * trace. If the edit is successful, the trace recorder will record it to the trace.
	 * 
	 * @return true to redirect
	 */
	protected boolean shouldWriteTarget() {
		return blockSet.provider.current.isAliveAndPresent();
	}

	/**
	 * Get the recorder.
	 * 
	 * <p>
	 * This should only be used for redirected writes. If we're not live, this will return null.
	 * 
	 * @return the recorder
	 */
	protected TraceRecorder getTraceRecorder() {
		return blockSet.provider.current.getRecorder();
	}

	@Override
	public void setByte(BigInteger index, byte value)
			throws ByteBlockAccessException {
		if (!shouldWriteTarget()) {
			super.setByte(index, value);
			return;
		}
		Address addr = getAddress(index);
		writeTargetByte(addr, value);
	}

	@Override
	public void setInt(BigInteger index, int value)
			throws ByteBlockAccessException {
		if (!shouldWriteTarget()) {
			super.setInt(index, value);
			return;
		}
		Address addr = getAddress(index);
		writeTargetInt(addr, value, isBigEndian());
	}

	@Override
	public void setLong(BigInteger index, long value)
			throws ByteBlockAccessException {
		if (!shouldWriteTarget()) {
			super.setLong(index, value);
			return;
		}
		Address addr = getAddress(index);
		writeTargetLong(addr, value, isBigEndian());
	}

	/**
	 * Write an array of bytes to the target's memory.
	 * 
	 * @param addr the starting address
	 * @param data the data to write, prepared in correct endianness
	 */
	public void writeTarget(Address addr, byte[] data) {
		TraceRecorder recorder = getTraceRecorder();
		recorder.writeProcessMemory(addr, data);
	}

	/**
	 * Allocate a buffer for encoding values into bytes.
	 * 
	 * @param size the number of bytes to allocate
	 * @param bigEndian true to order the buffer in {@link ByteOrder#BIG_ENDIAN}.
	 * @return the buffer, allocated and configured.
	 */
	protected ByteBuffer newBuffer(int size, boolean bigEndian) {
		ByteBuffer buf = ByteBuffer.allocate(size);
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		return buf;
	}

	/**
	 * Write a single byte to the target.
	 * 
	 * <p>
	 * Endianness is meaningless
	 * 
	 * @param addr the address
	 * @param value the byte
	 */
	public void writeTargetByte(Address addr, byte value) {
		writeTarget(addr, new byte[] { value });
	}

	/**
	 * Write a single int to the target
	 * 
	 * @param addr the minimum address to modify
	 * @param value the integer
	 * @param bigEndian true for big endian, false for little
	 */
	public void writeTargetInt(Address addr, int value, boolean bigEndian) {
		ByteBuffer buf = newBuffer(Integer.BYTES, bigEndian);
		buf.putInt(value);
		writeTarget(addr, buf.array());
	}

	/**
	 * Write a single long to the target
	 * 
	 * @param addr the minimum address to modify
	 * @param value the long
	 * @param bigEndian true for big endian, false for little
	 */
	public void writeTargetLong(Address addr, long value, boolean bigEndian) {
		ByteBuffer buf = newBuffer(Long.BYTES, bigEndian);
		buf.putLong(value);
		writeTarget(addr, buf.array());
	}

	@Override
	protected boolean editAllowed(Address addr, long length) {
		/**
		 * Traces are much more permissive when it comes to writes. The instruction will just get
		 * clobbered, from this time forward.
		 */
		return true;
	}
}
