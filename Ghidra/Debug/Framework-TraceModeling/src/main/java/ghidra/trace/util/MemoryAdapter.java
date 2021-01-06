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
package ghidra.trace.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public interface MemoryAdapter extends Memory {

	default ByteBuffer mustRead(Address addr, int length, boolean bigEndian)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(length);
		if (getBytes(addr, buf.array()) != length) {
			throw new MemoryAccessException();
		}
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		return buf;
	}

	@Override
	default int getBytes(Address addr, byte[] dest) throws MemoryAccessException {
		return getBytes(addr, dest, 0, dest.length);
	}

	@Override
	default byte getByte(Address addr) throws MemoryAccessException {
		return mustRead(addr, Byte.BYTES, true).get(0);
	}

	@Override
	default short getShort(Address addr) throws MemoryAccessException {
		return mustRead(addr, Short.BYTES, true).getShort(0);
	}

	@Override
	default short getShort(Address addr, boolean bigEndian) throws MemoryAccessException {
		return mustRead(addr, Short.BYTES, bigEndian).getShort(0);
	}

	@Override
	default int getShorts(Address addr, short[] dest) throws MemoryAccessException {
		return getShorts(addr, dest, 0, dest.length, true);
	}

	@Override
	default int getShorts(Address addr, short[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return getShorts(addr, dest, dIndex, nElem, true);
	}

	@Override
	default int getShorts(Address addr, short[] dest, int dIndex, int nElem, boolean bigEndian)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(Short.BYTES * nElem);
		int got = getBytes(addr, buf.array()) / Short.BYTES;
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.asShortBuffer().get(dest, dIndex, got);
		return got;
	}

	@Override
	default int getInt(Address addr) throws MemoryAccessException {
		return mustRead(addr, Integer.BYTES, true).getInt(0);
	}

	@Override
	default int getInt(Address addr, boolean bigEndian) throws MemoryAccessException {
		return mustRead(addr, Integer.BYTES, bigEndian).getInt(0);
	}

	@Override
	default int getInts(Address addr, int[] dest) throws MemoryAccessException {
		return getInts(addr, dest, 0, dest.length, true);
	}

	@Override
	default int getInts(Address addr, int[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return getInts(addr, dest, dIndex, nElem, true);
	}

	@Override
	default int getInts(Address addr, int[] dest, int dIndex, int nElem, boolean bigEndian)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES * nElem);
		int got = getBytes(addr, buf.array()) / Integer.BYTES;
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.asIntBuffer().get(dest, dIndex, got);
		return got;
	}

	@Override
	default long getLong(Address addr) throws MemoryAccessException {
		return mustRead(addr, Long.BYTES, true).getLong(0);
	}

	@Override
	default long getLong(Address addr, boolean bigEndian) throws MemoryAccessException {
		return mustRead(addr, Long.BYTES, bigEndian).getLong(0);
	}

	@Override
	default int getLongs(Address addr, long[] dest) throws MemoryAccessException {
		return getLongs(addr, dest, 0, dest.length, true);
	}

	@Override
	default int getLongs(Address addr, long[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return getLongs(addr, dest, dIndex, nElem, true);
	}

	@Override
	default int getLongs(Address addr, long[] dest, int dIndex, int nElem, boolean bigEndian)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(Long.BYTES * nElem);
		int got = getBytes(addr, buf.array()) / Long.BYTES;
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.asLongBuffer().get(dest, dIndex, got);
		return got;
	}

	@Override
	default void setBytes(Address addr, byte[] source) throws MemoryAccessException {
		setBytes(addr, source, 0, source.length);
	}

	@Override
	default void setByte(Address addr, byte value) throws MemoryAccessException {
		setBytes(addr, new byte[] { value });
	}

	@Override
	default void setShort(Address addr, short value) throws MemoryAccessException {
		setShort(addr, value, true);
	}

	@Override
	default void setShort(Address addr, short value, boolean bigEndian)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(Short.BYTES);
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.putShort(value);
		setBytes(addr, buf.array());
	}

	@Override
	default void setInt(Address addr, int value) throws MemoryAccessException {
		setInt(addr, value, true);
	}

	@Override
	default void setInt(Address addr, int value, boolean bigEndian) throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.putInt(value);
		setBytes(addr, buf.array());
	}

	@Override
	default void setLong(Address addr, long value) throws MemoryAccessException {
		setLong(addr, value, true);
	}

	@Override
	default void setLong(Address addr, long value, boolean bigEndian) throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(Long.BYTES);
		buf.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.putLong(value);
		setBytes(addr, buf.array());
	}
}
