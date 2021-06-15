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

import db.DBRecord;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Implementation of SubMemoryBlock for uninitialized blocks.
 */
class UninitializedSubMemoryBlock extends SubMemoryBlock {

	UninitializedSubMemoryBlock(MemoryMapDBAdapter adapter, DBRecord record) {
		super(adapter, record);
	}

	@Override
	public boolean isInitialized() {
		return false;
	}

	@Override
	public byte getByte(long offset) throws MemoryAccessException {
		if (offset < subBlockOffset || offset >= subBlockOffset + subBlockLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + "is out of bounds. Should be in [" + subBlockOffset + "," +
					(subBlockOffset + subBlockLength - 1));
		}
		throw new MemoryAccessException("Attempted to read from uninitialized block");
	}

	@Override
	public int getBytes(long offset, byte[] b, int off, int len) throws MemoryAccessException {
		throw new MemoryAccessException("Attempted to read from uninitialized block");
	}

	@Override
	public void putByte(long offset, byte b) throws MemoryAccessException {
		throw new MemoryAccessException("Attempted to write to an uninitialized block");
	}

	@Override
	public int putBytes(long offset, byte[] b, int off, int len) throws MemoryAccessException {
		throw new MemoryAccessException("Attempted to write to an uninitialized block");
	}

	@Override
	protected boolean join(SubMemoryBlock block) throws IOException {
		if (!(block instanceof UninitializedSubMemoryBlock)) {
			return false;
		}
		setLength(subBlockLength + block.subBlockLength);
		adapter.deleteSubBlock(block.record.getKey());
		return true;
	}

	@Override
	protected SubMemoryBlock split(long memBlockOffset) throws IOException {
		// convert from offset in block to offset in this sub block
		long offset = memBlockOffset - subBlockOffset;
		long newLength = subBlockLength - offset;
		subBlockLength = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, subBlockLength);
		adapter.updateSubBlockRecord(record);

		DBRecord newSubRecord = adapter.createSubBlockRecord(-1, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_UNITIALIZED, 0, 0);

		return new UninitializedSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		return "";
	}

}
