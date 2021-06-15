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

import db.DBBuffer;
import db.DBRecord;
import ghidra.program.model.mem.Memory;

/**
 * Implementation of SubMemoryBlock for blocks that store bytes in their own private database
 * buffers
 */
class BufferSubMemoryBlock extends SubMemoryBlock {
	final DBBuffer buf;

	BufferSubMemoryBlock(MemoryMapDBAdapter adapter, DBRecord record) throws IOException {
		super(adapter, record);
		int bufferID = record.getIntValue(MemoryMapDBAdapter.SUB_INT_DATA1_COL);
		buf = adapter.getBuffer(bufferID);
	}

	@Override
	public boolean isInitialized() {
		return true;
	}

	@Override
	public byte getByte(long offsetInMemBlock) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		return buf.getByte((int) offsetInSubBlock);
	}

	@Override
	public int getBytes(long offsetInMemBlock, byte[] b, int off, int len) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		long available = subBlockLength - offsetInSubBlock;
		len = (int) Math.min(len, available);
		buf.get((int) offsetInSubBlock, b, off, len);
		return len;
	}

	@Override
	public void putByte(long offsetInMemBlock, byte b) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		buf.putByte((int) offsetInSubBlock, b);
	}

	@Override
	public int putBytes(long offsetInMemBlock, byte[] b, int off, int len) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		long available = subBlockLength - offsetInSubBlock;
		len = (int) Math.min(len, available);
		buf.put((int) offsetInSubBlock, b, off, len);
		return len;
	}

	@Override
	public void delete() throws IOException {
		buf.delete();
		super.delete();
	}

	@Override
	protected boolean join(SubMemoryBlock block) throws IOException {
		if (!(block instanceof BufferSubMemoryBlock)) {
			return false;
		}
		BufferSubMemoryBlock other = (BufferSubMemoryBlock) block;
		if (other.subBlockLength + subBlockLength > Memory.GBYTE) {
			return false;
		}
		buf.append(other.buf);
		setLength(subBlockLength + other.subBlockLength);
		adapter.deleteSubBlock(other.record.getKey());
		return true;
	}

	long getKey() {
		return record.getKey();
	}

	@Override
	protected SubMemoryBlock split(long memBlockOffset) throws IOException {
		// convert from offset in block to offset in this sub block
		int offset = (int) (memBlockOffset - subBlockOffset);
		long newLength = subBlockLength - offset;
		subBlockLength = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, subBlockLength);
		adapter.updateSubBlockRecord(record);

		DBBuffer split = buf.split(offset);

		DBRecord newSubRecord = adapter.createSubBlockRecord(0, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_BUFFER, split.getId(), 0);

		return new BufferSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		return "";
	}
}
