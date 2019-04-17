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
package ghidra.program.model.util;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Class to iterate over the bytes in memory for an address set.
 */
public class MemoryByteIterator {
	private static final int BUF_SIZE = 16 * 1024;
	private Memory mem;
	private AddressSet addrSet;
	byte[] buf;
	int count = 0;
	int pos;

	/**
	 * Construct a memoryIterator
	 * @param mem the memory providing the bytes
	 * @param set the set of addresses for which to iterate bytes
	 */
	public MemoryByteIterator(Memory mem, AddressSetView set) {
		this.mem = mem;
		addrSet = set.intersect(mem);
		buf = new byte[BUF_SIZE];

	}

	/**
	 * Returns true if there are more bytes to iterate over
	 */
	public boolean hasNext() {
		return count != 0 || !addrSet.isEmpty();
	}

	/**
	 * Returns the next byte.
	 * @throws MemoryAccessException if the next byte could not be read
	 */
	public byte next() throws MemoryAccessException {
		if (count == 0) {
			AddressRange range = addrSet.iterator().next();
			Address start = range.getMinAddress();
			long size = range.getLength();
			if (size > BUF_SIZE) {
				range = new AddressRangeImpl(start, start.add(BUF_SIZE - 1));
				size = BUF_SIZE;
			}
			count = (int) size;
			pos = 0;
			addrSet.delete(range);

			mem.getBytes(start, buf, 0, count);
		}
		count--;
		return buf[pos++];
	}

}
