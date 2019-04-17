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

public interface GhidraDataConverter extends DataConverter {

	/**
	 * Generate a little-endian short value by invoking buf.getBytes at the specified offset.
	 * @param buf
	 * @param offset
	 * @return little-endian short value
	 * @throws MemoryAccessException if failed to read 2-bytes at the specified offset
	 */
	public short getShort(MemBuffer buf, int offset) throws MemoryAccessException;

	/**
	 * Generate a little-endian int value by invoking buf.getBytes at the specified offset.
	 * @param buf
	 * @param offset
	 * @return little-endian int value
	 * @throws MemoryAccessException if failed to read 4-bytes at the specified offset
	 */
	public int getInt(MemBuffer buf, int offset) throws MemoryAccessException;

	/**
	 * Generate a little-endian long value by invoking buf.getBytes at the specified offset.
	 * @param buf
	 * @param offset
	 * @return little-endian long value
	 * @throws MemoryAccessException if failed to read 8-bytes at the specified offset
	 */
	public long getLong(MemBuffer buf, int offset) throws MemoryAccessException;

	/**
	 * Generate a little-endian BigInteger value by invoking buf.getBytes at the specified offset.
	 * @param buf
	 * @param offset
	 * @return little-endian BigInteger value
	 * @throws MemoryAccessException if failed to read specified number of bytes
	 * at the specified offset
	 */
	public BigInteger getBigInteger(MemBuffer buf, int offset, int size, boolean signed)
			throws MemoryAccessException;
	
}
