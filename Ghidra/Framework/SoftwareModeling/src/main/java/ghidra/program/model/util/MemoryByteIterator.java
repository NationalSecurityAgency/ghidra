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

import java.util.Iterator;
import java.util.NoSuchElementException;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Class to iterate over the bytes in memory for an address set.
 */
public class MemoryByteIterator implements Iterator<Byte> {
	public static final int MAX_BUF_SIZE = 16 * 1024;
	private Memory mem;
	private AddressSet addrSet;

	private byte[] buf;
	private int bufSize;
	private int pos;

	/**
	 * Construct a memoryIterator
	 * @param mem the memory providing the bytes
	 * @param set the set of addresses for which to iterate bytes
	 */
	public MemoryByteIterator(Memory mem, AddressSetView set) {
		this.mem = mem;
		this.addrSet = set.intersect(mem);
		this.buf = new byte[(int) Math.min(MAX_BUF_SIZE, set.getNumAddresses())];
	}

	@Override
	public boolean hasNext() {
		ensureBuffer();
		return pos < bufSize;
	}

	@Override
	public Byte next() {
		return nextByte();
	}

	/**
	 * {@return the next primitive byte.  Use this method if you want to avoid the cost of
	 * boxing Bytes the normal next() method returns}
	 * 
	 * @throws NoSuchElementException if the iteration has no more elements
	 */
	public byte nextByte() {
		ensureBuffer();
		if (pos < bufSize) {
			byte result = buf[pos];
			pos++;
			return result;
		}
		throw new NoSuchElementException();
	}

	private void ensureBuffer() {
		if (pos >= bufSize && !addrSet.isEmpty()) {
			AddressRange firstRange = addrSet.getFirstRange();
			Address addr = firstRange.getMinAddress();

			int readSize = (int) Math.min(firstRange.getLength(), buf.length);
			addrSet.deleteFromMin(addr.add(readSize - 1)); // remove from addrSet before possible exception in getBytes()

			pos = 0;
			try {
				bufSize = mem.getBytes(addr, buf, 0, readSize);
			}
			catch (MemoryAccessException e) {
				bufSize = 0;
			}
		}
	}

}
