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

import java.io.IOException;
import java.nio.ByteBuffer;

import db.DBRecord;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.OffsetSnap;
import ghidra.trace.database.DBTraceUtils.OffsetThenSnapDBFieldCodec;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
class DBTraceMemoryBlockEntry extends DBAnnotatedObject {
	private static final String TABLE_NAME = "MemoryBlocks";

	static final String LOCATION_COLUMN_NAME = "LocationOT";
	static final String BUFFER_COLUMN_NAME = "Buffer";
	static final String BLOCK_COLUMN_NAME = "Block";

	@DBAnnotatedColumn(LOCATION_COLUMN_NAME)
	static DBObjectColumn LOCATION_COLUMN;
	@DBAnnotatedColumn(BUFFER_COLUMN_NAME)
	static DBObjectColumn BUFFER_COLUMN;
	@DBAnnotatedColumn(BLOCK_COLUMN_NAME)
	static DBObjectColumn BLOCK_COLUMN;

	static String tableName(AddressSpace space, long threadKey, int frameLevel) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
	}

	@DBAnnotatedField(column = LOCATION_COLUMN_NAME, indexed = true, codec = OffsetThenSnapDBFieldCodec.class)
	private OffsetSnap location;
	@DBAnnotatedField(column = BUFFER_COLUMN_NAME)
	private long bufferKey = -1;
	@DBAnnotatedField(column = BLOCK_COLUMN_NAME)
	private byte blockNum = -1;

	private final DBTraceMemorySpace space;

	public DBTraceMemoryBlockEntry(DBTraceMemorySpace space, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.space = space;
	}

	public void setLoc(OffsetSnap location) {
		this.location = location;
		update(LOCATION_COLUMN);
	}

	public long getOffset() {
		return location.offset;
	}

	public long getSnap() {
		return location.snap;
	}

	private int getBlockNumber() {
		return Byte.toUnsignedInt(blockNum);
	}

	public DBTraceMemoryBlockEntry copy(OffsetSnap loc) throws IOException {
		assert loc.offset == location.offset;
		assert loc.snap > location.snap;
		DBTraceMemoryBlockEntry cp = space.blockStore.create();
		cp.setLoc(loc);
		DBTraceMemoryBufferEntry myBuf = findAssignedBuffer();
		if (myBuf == null) {
			return cp;
		}
		DBTraceMemoryBufferEntry cpBuf = cp.findFreeBuffer(myBuf);
		if (cpBuf == null) {
			cpBuf = cp.findFreeBufferInFuture();
			if (cpBuf == null) {
				cpBuf = cp.allocateNewBuffer();
			}
		}
		cpBuf.copyFrom(cp.getBlockNumber(), myBuf, getBlockNumber());
		return cp;
	}

	protected DBTraceMemoryBufferEntry allocateNewBuffer() {
		DBTraceMemoryBufferEntry bufEnt = space.bufferStore.create();
		bufferKey = bufEnt.getKey();
		bufEnt.acquireBlock(0);
		blockNum = 0;
		update(BUFFER_COLUMN, BLOCK_COLUMN);
		return bufEnt;
	}

	protected DBTraceMemoryBufferEntry findFreeBuffer(DBTraceMemoryBufferEntry bufEnt) {
		if (bufEnt == null) {
			return null;
		}
		blockNum = (byte) bufEnt.acquireBlock();
		if (blockNum == -1) {
			return null;
		}
		bufferKey = bufEnt.getKey();
		update(BUFFER_COLUMN, BLOCK_COLUMN);
		return bufEnt;
	}

	protected DBTraceMemoryBufferEntry findFreeBuffer(DBTraceMemoryBlockEntry prev)
			throws IOException {
		DBTraceMemoryBufferEntry bufEnt = prev.findAssignedBuffer();
		return findFreeBuffer(bufEnt);
	}

	protected DBTraceMemoryBufferEntry findFreeBufferInPast() throws IOException {
		DBTraceMemoryBlockEntry prev = space.findMostRecentBlockEntry(location, false);
		if (prev == null) {
			return null;
		}
		return findFreeBuffer(prev);
	}

	protected DBTraceMemoryBufferEntry findFreeBufferInFuture() throws IOException {
		DBTraceMemoryBlockEntry prev = space.findSoonestBlockEntry(location, false);
		if (prev == null) {
			return null;
		}
		return findFreeBuffer(prev);
	}

	protected DBTraceMemoryBufferEntry findFreeBuffer() throws IOException {
		DBTraceMemoryBufferEntry ent = findFreeBufferInPast();
		if (ent != null) {
			return ent;
		}
		ent = findFreeBufferInFuture();
		if (ent != null) {
			return ent;
		}
		return allocateNewBuffer();
	}

	protected DBTraceMemoryBufferEntry findAssignedBuffer() throws IOException {
		if (bufferKey == -1) {
			return null;
		}
		DBTraceMemoryBufferEntry bufEnt = space.bufferStore.getObjectAt(bufferKey);
		if (bufEnt == null) {
			throw new IOException("Trace Bytes table is corrupt");
		}
		return bufEnt;
	}

	protected static boolean isZeroes(ByteBuffer buf, int len) {
		int pos = buf.position();
		for (int i = 0; i < len; i++) {
			if (buf.get(pos + i) != 0) {
				return false;
			}
		}
		return true;
	}

	public int setBytes(ByteBuffer buf, int dstOffset, int len) throws IOException {
		DBTraceMemoryBufferEntry bufEnt = findAssignedBuffer();
		if (bufEnt == null) {
			if (isZeroes(buf, len)) {
				buf.position(buf.position() + len);
				return len;
			}
			bufEnt = findFreeBuffer();
		}
		return bufEnt.setBytes(buf, dstOffset, len, getBlockNumber());
	}

	public int getBytes(ByteBuffer buf, int srcOffset, int len) throws IOException {
		DBTraceMemoryBufferEntry bufEnt = findAssignedBuffer();
		if (bufEnt == null) {
			buf.put(new byte[len]); // Ew.
			return len;
		}
		return bufEnt.getBytes(buf, srcOffset, len, getBlockNumber());
	}

	public int cmpBytes(ByteBuffer buf, int dstOffset, int len) throws IOException {
		DBTraceMemoryBufferEntry bufEnt = findAssignedBuffer();
		if (bufEnt == null) {
			if (isZeroes(buf, len)) {
				return 0;
			}
			return -1;
		}
		return bufEnt.cmpBytes(buf, dstOffset, len, getBlockNumber());
	}
}
