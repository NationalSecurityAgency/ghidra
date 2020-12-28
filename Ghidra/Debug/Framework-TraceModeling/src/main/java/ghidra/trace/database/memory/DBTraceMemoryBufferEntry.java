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
package ghidra.trace.database.memory;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import db.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceMemoryBufferEntry extends DBAnnotatedObject {
	private static final String TABLE_NAME = "MemoryBuffers";

	static final String IN_USE_COLUMN_NAME = "InUse";
	static final String BUFFER_ID_COLUMN_NAME = "BufferId";
	static final String COMPRESSED_COLUMN_NAME = "Compressed";

	@DBAnnotatedColumn(IN_USE_COLUMN_NAME)
	static DBObjectColumn IN_USE_COLUMN;
	@DBAnnotatedColumn(BUFFER_ID_COLUMN_NAME)
	static DBObjectColumn BUFFER_ID_COLUMN;
	@DBAnnotatedColumn(COMPRESSED_COLUMN_NAME)
	static DBObjectColumn COMPRESSED_COLUMN;

	static String tableName(AddressSpace space, long threadKey, int frameLevel) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
	}

	@DBAnnotatedField(column = IN_USE_COLUMN_NAME)
	private byte[] inUse = new byte[DBTraceMemorySpace.BLOCKS_PER_BUFFER / Byte.SIZE];
	@DBAnnotatedField(column = BUFFER_ID_COLUMN_NAME)
	private int bufferId = -1;
	@DBAnnotatedField(column = COMPRESSED_COLUMN_NAME)
	private boolean compressed;

	protected final DBHandle dbh;

	private DBBuffer buffer;

	public DBTraceMemoryBufferEntry(DBHandle dbh, DBCachedObjectStore<?> store, DBRecord record) {
		super(store, record);
		this.dbh = dbh;
	}

	protected boolean isCompressed() {
		return compressed;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			buffer = dbh.createBuffer(
				DBTraceMemorySpace.BLOCKS_PER_BUFFER << DBTraceMemorySpace.BLOCK_SHIFT);
			bufferId = buffer.getId();
		}
		else {
			buffer = dbh.getBuffer(bufferId);
		}
	}

	public void compress() throws IOException {
		if (compressed) {
			return;
		}
		DBBuffer newBuffer = dbh.createBuffer(buffer.length());
		try (InputStream is = new DBBufferInputStream(buffer);
				OutputStream os = new GZIPOutputStream(new DBBufferOutputStream(newBuffer),
					DBTraceMemorySpace.BLOCK_SIZE * 2);) {
			is.transferTo(os);
		}
		buffer.delete();
		buffer = newBuffer;
		bufferId = buffer.getId();
		compressed = true;
		update(BUFFER_ID_COLUMN, COMPRESSED_COLUMN);
	}

	public void decompress() throws IOException {
		if (!compressed) {
			return;
		}
		DBBuffer newBuffer = dbh
				.createBuffer(
					DBTraceMemorySpace.BLOCKS_PER_BUFFER << DBTraceMemorySpace.BLOCK_SHIFT);
		try (InputStream is = new GZIPInputStream(new DBBufferInputStream(buffer));
				OutputStream os = new DBBufferOutputStream(newBuffer);) {
			is.transferTo(os);
		}
		buffer.delete();
		buffer = newBuffer;
		bufferId = buffer.getId();
		compressed = false;
		update(BUFFER_ID_COLUMN, COMPRESSED_COLUMN);
	}

	protected boolean isSane(int offset, int len, int blockNum) {
		if (offset + len > DBTraceMemorySpace.BLOCK_SIZE) {
			return false;
		}
		if (blockNum >= DBTraceMemorySpace.BLOCKS_PER_BUFFER) {
			return false;
		}
		if (!isInUse(blockNum)) {
			return false;
		}
		return true;
	}

	public int setBytes(ByteBuffer buf, int dstOffset, int len, int blockNum) throws IOException {
		assert isSane(dstOffset, len, blockNum);
		if (compressed) {
			decompress();
		}
		buffer.put((blockNum << DBTraceMemorySpace.BLOCK_SHIFT) + dstOffset, buf.array(),
			buf.arrayOffset() + buf.position(), len);
		buf.position(buf.position() + len);
		return len;
	}

	public int getBytes(ByteBuffer buf, int srcOffset, int len, int blockNum) throws IOException {
		assert isSane(srcOffset, len, blockNum);
		if (compressed) {
			return doGetCompressedBytes(buf, srcOffset, len, blockNum);
		}
		buffer.get((blockNum << DBTraceMemorySpace.BLOCK_SHIFT) + srcOffset, buf.array(),
			buf.arrayOffset() + buf.position(), len);
		buf.position(buf.position() + len);
		return len;
	}

	protected int doGetCompressedBytes(ByteBuffer buf, int srcOffset, int len, int blockNum)
			throws IOException {
		try (InputStream is = new GZIPInputStream(new DBBufferInputStream(buffer))) {
			is.skip((blockNum << DBTraceMemorySpace.BLOCK_SHIFT) + srcOffset);
			int amt = is.read(buf.array(), buf.arrayOffset() + buf.position(), len);
			buf.position(buf.position() + amt);
			if (amt != len) {
				// There should always be enough
				throw new IOException("compressed memory buffer is corrupt");
			}
			return len;
		}
	}

	protected void doGetBlock(int blockNum, byte[] data) throws IOException {
		assert isInUse(blockNum);
		if (compressed) {
			doGetCompressedBlock(blockNum, data);
		}
		buffer.get(blockNum << DBTraceMemorySpace.BLOCK_SHIFT, data);
	}

	protected void doGetCompressedBlock(int blockNum, byte[] data) throws IOException {
		try (InputStream is = new GZIPInputStream(new DBBufferInputStream(buffer))) {
			is.skip(blockNum << DBTraceMemorySpace.BLOCK_SHIFT);
			int amt = is.read(data);
			if (amt != data.length) {
				throw new IOException("compressed memory buffer is corrupt");
			}
		}
	}

	public void copyFrom(int dstBlockNum, DBTraceMemoryBufferEntry srcBuf, int srcBlockNum)
			throws IOException {
		assert isInUse(dstBlockNum);
		if (compressed) {
			decompress();
		}
		byte[] data = new byte[DBTraceMemorySpace.BLOCK_SIZE];
		srcBuf.doGetBlock(srcBlockNum, data);
		buffer.put(dstBlockNum << DBTraceMemorySpace.BLOCK_SHIFT, data);
	}

	public int cmpBytes(ByteBuffer buf, int blkOffset, int len, int blockNum) throws IOException {
		assert isSane(blkOffset, len, blockNum);
		if (compressed) {
			return doCmpCompressedBytes(buf, blkOffset, len, blockNum);
		}
		int leftPos = (blockNum << DBTraceMemorySpace.BLOCK_SHIFT) + blkOffset;
		int rightPos = buf.position();
		for (int i = 0; i < len; i++) {
			byte left = buffer.getByte(leftPos + i);
			byte right = buf.get(rightPos + i);
			int cmp = Byte.compareUnsigned(left, right);
			if (cmp != 0) {
				return cmp;
			}
		}
		return 0;
	}

	protected int doCmpCompressedBytes(ByteBuffer buf, int blkOffset, int len, int blockNum)
			throws IOException {
		try (InputStream is = new GZIPInputStream(new DBBufferInputStream(buffer))) {
			is.skip((blockNum << DBTraceMemorySpace.BLOCK_SHIFT) + blkOffset);
			int rightPos = buf.position();
			for (int i = 0; i < len; i++) {
				int left = is.read();
				if (left == -1) {
					// There should always be enough
					throw new IOException("compressed memory buffer is corrupt");
				}
				byte right = buf.get(rightPos + i);
				int cmp = Byte.compareUnsigned((byte) left, right);
				if (cmp != 0) {
					return cmp;
				}
			}
			return 0;
		}
	}

	public boolean isInUse(int blockNum) {
		int i = blockNum >> 3;
		int j = blockNum & 0x7;
		return (inUse[i] & (1 << j)) != 0;
	}

	public int acquireBlock() {
		for (int i = 0; i < inUse.length; i++) {
			byte b = inUse[i];
			if (b == -1) {
				continue;
			}
			for (int j = 0; j < Byte.SIZE; j++) {
				if ((b & (1 << j)) == 0) {
					inUse[i] |= 1 << j;
					update(IN_USE_COLUMN);
					return i * Byte.SIZE + j;
				}
			}
		}
		return -1;
	}

	public void acquireBlock(int blockNum) {
		int i = blockNum >> 3;
		int j = blockNum & 7;
		assert (inUse[i] & (1 << j)) == 0;
		inUse[i] |= (1 << j);
		update(IN_USE_COLUMN);
	}

	public void releaseBlock(int blockNum) {
		int i = blockNum >> 3;
		int j = blockNum & 0x7;
		assert (inUse[i] & (1 << j)) != 0;
		inUse[i] &= ~(1 << j);
		update(IN_USE_COLUMN);
	}

	public boolean isEmpty() {
		for (int i = 0; i < inUse.length; i++) {
			if (inUse[i] != 0) {
				return false;
			}
		}
		return true;
	}
}
