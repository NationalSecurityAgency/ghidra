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
package ghidra.util.database;

import java.io.IOException;
import java.io.InputStream;

import db.DBBuffer;

/**
 * An input stream backed by a database chained buffer
 */
public class DBBufferInputStream extends InputStream {
	protected final DBBuffer buffer;

	protected int offset;
	protected int mark = -1;

	public DBBufferInputStream(DBBuffer buffer) {
		this.buffer = buffer;
		this.offset = 0;
	}

	@Override
	public int available() throws IOException {
		return buffer.length() - offset;
	}

	@Override
	public synchronized void mark(int readlimit) {
		mark = offset;
	}

	@Override
	public boolean markSupported() {
		return true;
	}

	@Override
	public int read(byte[] b) throws IOException {
		if (offset == buffer.length()) {
			return -1;
		}
		int len = Math.min(available(), b.length);
		buffer.get(offset, b, 0, len);
		offset += len;
		return len;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (offset == buffer.length()) {
			return -1;
		}
		len = Math.min(available(), len);
		buffer.get(offset, b, off, len);
		offset += len;
		return len;
	}

	@Override
	public int read() throws IOException {
		if (offset == buffer.length()) {
			return -1;
		}
		return 0xff & buffer.getByte(offset++);

	}

	@Override
	public byte[] readAllBytes() throws IOException {
		byte[] result = new byte[available()];
		buffer.get(offset, result);
		offset += result.length;
		return result;
	}

	@Override
	public int readNBytes(byte[] b, int off, int len) throws IOException {
		return read(b, off, len);
	}

	@Override
	public byte[] readNBytes(int len) throws IOException {
		len = Math.min(available(), len);
		byte[] result = new byte[len];
		buffer.get(offset, result);
		offset += len;
		return result;
	}

	@Override
	public synchronized void reset() throws IOException {
		if (mark == -1) {
			throw new IOException("No mark");
		}
		offset = mark;
	}

	@Override
	public long skip(long n) throws IOException {
		if (n < 0) {
			return 0;
		}
		n = Math.min(available(), n);
		offset += n;
		return n;
	}
}
