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
package ghidra.program.database.mem;

import java.io.IOException;
import java.io.InputStream;

import ghidra.program.model.mem.MemoryAccessException;

/**
 * Maps a MemoryBlockDB into an InputStream.
 */
class MemoryBlockInputStream extends InputStream {
	private long index = 0;
	private long resetIndex = 0;
	private long numBytes = 0;
	MemoryBlockDB block;

	/**
	 * Constructs a new MemoryBlockInputStream for reading the bytes of a memory block.
	 * @param block the memory block whose bytes are to be read as an input stream.
	 */
	MemoryBlockInputStream(MemoryBlockDB block) {
		this.block = block;
		if (!block.isInitialized()) {
			numBytes = 0;
		}
		else {
			numBytes = (int) block.getSize();
		}
	}

	/**
	 * @see java.io.InputStream#available()
	 */
	@Override
	public int available() throws IOException {
		return (int) Math.min(Integer.MAX_VALUE, numBytes - index);
	}

	/**
	 * @see java.io.InputStream#mark(int)
	 */
	@Override
	public synchronized void mark(int readlimit) {
		resetIndex = index;
	}

	/**
	 * @see java.io.InputStream#markSupported()
	 */
	@Override
	public boolean markSupported() {
		return true;
	}

	/**
	 * @see java.io.InputStream#reset()
	 */
	@Override
	public synchronized void reset() throws IOException {
		index = resetIndex;
	}

	/**
	 * @see java.io.InputStream#skip(long)
	 */
	@Override
	public long skip(long n) throws IOException {
		long numSkipped = Math.min(n, numBytes - index);
		index += numSkipped;
		return numSkipped;
	}

	/**
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		if (index >= numBytes) {
			return -1;
		}
		try {
			return block.getByte(index++) & 0xff;
		}
		catch (MemoryAccessException e) {
			throw new IOException(e);
		}
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (index >= numBytes) {
			return -1;
		}
		long remaining = numBytes - index;
		if (remaining < len) {
			len = (int) remaining;
		}
		try {
			len = block.getBytes(index, b, off, len);
			index += len;
			return len;
		}
		catch (MemoryAccessException e) {
			throw new IOException(e);
		}
	}

}
