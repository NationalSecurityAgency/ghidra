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
package ghidra.trace.model.memory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import ghidra.program.model.address.*;
import ghidra.trace.model.program.TraceProgramView;

public class TraceMemorySpaceInputStream extends InputStream {
	private final TraceProgramView program;
	private final TraceMemorySpace space;
	private final Address start;
	private final Address end;

	private long mark = -1;
	private long pos;

	public TraceMemorySpaceInputStream(TraceProgramView program, TraceMemorySpace space,
			AddressRange range) {
		this.program = program;
		this.space = space;
		this.start = range.getMinAddress();
		this.end = range.getMaxAddress();
	}

	@Override
	public int read() throws IOException {
		if (available() <= 0) {
			return -1;
		}
		ByteBuffer buf = ByteBuffer.allocate(1);
		try {
			if (space.getBytes(program.getSnap(), start.addNoWrap(pos), buf) == 0) {
				return -1;
			}
			pos++;
			return buf.get(0) & 0xff;
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		ByteBuffer buf = ByteBuffer.wrap(b, off, len);
		buf.limit(Math.min(available(), len));
		try {
			return space.getBytes(program.getSnap(), start.addNoWrap(pos), buf);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public int available() throws IOException {
		return (int) Math.min(Math.max(0, end.subtract(start) - pos + 1), Integer.MAX_VALUE);
	}

	@Override
	public boolean markSupported() {
		return true;
	}

	@Override
	public synchronized void mark(int readlimit) {
		mark = pos;
	}

	@Override
	public synchronized void reset() throws IOException {
		if (mark == -1) {
			throw new IOException();
		}
		pos = mark;
	}

	@Override
	public long skip(long n) throws IOException {
		if (n <= 0) {
			return 0;
		}
		long skipped = Math.min(available(), n);
		pos += skipped;
		return skipped;
	}
}
