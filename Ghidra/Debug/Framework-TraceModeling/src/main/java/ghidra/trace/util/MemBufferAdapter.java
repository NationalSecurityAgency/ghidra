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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

public interface MemBufferAdapter extends MemBuffer {
	int getBytes(ByteBuffer buffer, int addressOffset);

	@Override
	default byte getByte(int offset) throws MemoryAccessException {
		ByteBuffer buffer = ByteBuffer.allocate(1);
		if (getBytes(buffer, offset) < 1) {
			throw new MemoryAccessException(
				"Couldn't get requested byte for " + getClass().getSimpleName());
		}
		return buffer.get(0);
	}

	@Override
	default int getBytes(byte[] b, int offset) {
		return getBytes(ByteBuffer.wrap(b), offset);
	}

	default ByteBuffer getBytesInFull(int offset, int len) throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(len);
		if (getBytes(buf, offset) != len) {
			throw new MemoryAccessException("Could not read enough bytes");
		}
		if (!isBigEndian()) {
			buf.order(ByteOrder.LITTLE_ENDIAN);
		}
		return buf;
	}

	@Override
	default short getShort(int offset) throws MemoryAccessException {
		return getBytesInFull(offset, Short.BYTES).getShort(0);
	}

	@Override
	default int getInt(int offset) throws MemoryAccessException {
		return getBytesInFull(offset, Integer.BYTES).getInt(0);
	}

	@Override
	default long getLong(int offset) throws MemoryAccessException {
		return getBytesInFull(offset, Long.BYTES).getLong(0);
	}

	@Override
	default BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		byte[] buf = getBytesInFull(offset, size).array();
		if (!isBigEndian()) {
			ArrayUtils.reverse(buf);
		}
		if (signed) {
			return new BigInteger(buf);
		}
		return new BigInteger(1, buf);
	}
}
