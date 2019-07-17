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
package ghidra.util;

import java.math.BigInteger;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

public class GhidraBigEndianDataConverter extends BigEndianDataConverter implements GhidraDataConverter {

	@SuppressWarnings("hiding")
	public static final GhidraBigEndianDataConverter INSTANCE = new GhidraBigEndianDataConverter();

	@Override
	public final short getShort(MemBuffer buf, int offset) throws MemoryAccessException {
		byte[] bytes = new byte[2];
		if (buf.getBytes(bytes, offset) != 2) {
			throw new MemoryAccessException();
		}
		return getShort(bytes, 0);
	}

	@Override
	public final int getInt(MemBuffer buf, int offset) throws MemoryAccessException {
		byte[] bytes = new byte[4];
		if (buf.getBytes(bytes, offset) != 4) {
			throw new MemoryAccessException();
		}
		return getInt(bytes, 0);
	}

	@Override
	public final long getLong(MemBuffer buf, int offset) throws MemoryAccessException {
		byte[] bytes = new byte[8];
		if (buf.getBytes(bytes, offset) != 8) {
			throw new MemoryAccessException();
		}
		return getLong(bytes, 0);
	}

	@Override
	public final BigInteger getBigInteger(MemBuffer buf, int offset, int size, boolean signed)
			throws MemoryAccessException {
		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, offset) != size) {
			throw new MemoryAccessException();
		}
		return getBigInteger(bytes, size, signed);
	}

}
