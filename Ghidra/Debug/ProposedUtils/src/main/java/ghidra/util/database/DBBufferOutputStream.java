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
import java.io.OutputStream;

import db.DBBuffer;

/**
 * An output stream backed by a database chained buffer
 */
public class DBBufferOutputStream extends OutputStream {
	protected final DBBuffer buffer;
	protected final int increment;

	protected int offset;

	public DBBufferOutputStream(DBBuffer buffer) {
		this(buffer, 1024);
	}

	public DBBufferOutputStream(DBBuffer buffer, int increment) {
		this.buffer = buffer;
		this.increment = increment;
		this.offset = 0;
	}

	void checkExpand(int add) throws IOException {
		int len = offset + add;
		if (buffer.length() < len) {
			buffer.setSize(buffer.length() + increment, true);
		}
	}

	@Override
	public void write(byte[] b) throws IOException {
		checkExpand(b.length);
		buffer.put(offset, b);
		offset += b.length;
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		checkExpand(len);
		buffer.put(offset, b, off, len);
		offset += len;
	}

	@Override
	public void write(int b) throws IOException {
		checkExpand(1);
		buffer.putByte(offset, (byte) b);
		offset++;
	}

	@Override
	public void close() throws IOException {
		buffer.setSize(offset, true);
	}
}
