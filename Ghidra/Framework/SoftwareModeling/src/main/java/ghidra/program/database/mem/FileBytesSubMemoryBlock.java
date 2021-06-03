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
 * Class for handling {@link FileBytes} memory sub blocks (blocks whose bytes are backed by a FileBytes object
 */
class FileBytesSubMemoryBlock extends SubMemoryBlock {
	private final FileBytes fileBytes;
	private final long fileBytesOffset;

	FileBytesSubMemoryBlock(MemoryMapDBAdapter adapter, DBRecord record) throws IOException {
		super(adapter, record);
		long fileBytesID = record.getLongValue(MemoryMapDBAdapter.SUB_INT_DATA1_COL);
		fileBytesOffset = record.getLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL);
		fileBytes = adapter.getMemoryMap().getLayeredFileBytes(fileBytesID);
	}

	@Override
	public boolean isInitialized() {
		return true;
	}

	@Override
	public byte getByte(long offsetInMemBlock) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		return fileBytes.getModifiedByte(fileBytesOffset + offsetInSubBlock);
	}

	@Override
	public int getBytes(long offsetInMemBlock, byte[] b, int off, int len) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		long available = subBlockLength - offsetInSubBlock;
		len = (int) Math.min(len, available);
		return fileBytes.getModifiedBytes(fileBytesOffset + offsetInSubBlock, b, off, len);
	}

	@Override
	public void putByte(long offsetInMemBlock, byte b) throws MemoryAccessException, IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		fileBytes.putByte(fileBytesOffset + offsetInSubBlock, b);
	}

	@Override
	public int putBytes(long offsetInMemBlock, byte[] b, int off, int len) throws IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		long available = subBlockLength - offsetInSubBlock;
		len = (int) Math.min(len, available);
		return fileBytes.putBytes(fileBytesOffset + offsetInSubBlock, b, off, len);
	}

	@Override
	protected boolean join(SubMemoryBlock block) throws IOException {
		if (!(block instanceof FileBytesSubMemoryBlock)) {
			return false;
		}
		FileBytesSubMemoryBlock other = (FileBytesSubMemoryBlock) block;
		if (fileBytes != other.fileBytes) {
			return false;
		}
		// are the two block consecutive in the fileBytes space?
		if (other.fileBytesOffset != fileBytesOffset + subBlockLength) {
			return false;
		}
		// ok we can join them
		setLength(subBlockLength + other.subBlockLength);
		adapter.deleteSubBlock(other.record.getKey());
		return true;
	}

	public FileBytes getFileBytes() {
		return fileBytes;
	}

	public long getFileBytesOffset() {
		return fileBytesOffset;
	}

	@Override
	protected SubMemoryBlock split(long memBlockOffset) throws IOException {
		// convert from offset in block to offset in this sub block
		int offset = (int) (memBlockOffset - subBlockOffset);
		long newLength = subBlockLength - offset;
		subBlockLength = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, subBlockLength);
		adapter.updateSubBlockRecord(record);

		int fileBytesID = record.getIntValue(MemoryMapDBAdapter.SUB_INT_DATA1_COL);
		DBRecord newSubRecord = adapter.createSubBlockRecord(0, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_FILE_BYTES, fileBytesID, fileBytesOffset + offset);

		return new FileBytesSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		String fileName = fileBytes.getFilename();

		String hexString = Long.toHexString(fileBytesOffset + fileBytes.getFileOffset());
		return "File: " + fileName + ": 0x" + hexString;
	}

	@Override
	protected boolean uses(FileBytes fb) {
		return fileBytes.equals(fb);
	}

}
