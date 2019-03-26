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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class OmfIteratedData extends OmfRecord implements OmfData {

	public static final int MAX_ITERATED_FILL = 0x100000;	// Maximum number of bytes in expanded form
	private int segmentIndex;
	private long dataOffset;
	private DataBlock[] datablock;

	public OmfIteratedData(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		boolean hasBigFields = hasBigFields();
		segmentIndex = OmfRecord.readIndex(reader);
		dataOffset = OmfRecord.readInt2Or4(reader, hasBigFields);
		ArrayList<DataBlock> blocklist = new ArrayList<DataBlock>();
		while(reader.getPointerIndex() < max) {
			DataBlock block = DataBlock.read(reader, hasBigFields);
			blocklist.add(block);
		}
		readCheckSumByte(reader);
		datablock = new DataBlock[blocklist.size()];
		blocklist.toArray(datablock);
	}
	
	public int getSegmentIndex() {
		return segmentIndex;
	}

	@Override
	public long getDataOffset() {
		return dataOffset;
	}

	@Override
	public boolean isAllZeroes() {
		for (int i = 0; i < datablock.length; ++i) {
			if (!datablock[i].isAllZeroes()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int getLength() {
		int length = 0;
		for (DataBlock block : datablock) {
			length += block.getLength();
		}
		return length;
	}

	@Override
	public byte[] getByteArray(BinaryReader reader) throws IOException {
		int length = getLength();
		if (length > MAX_ITERATED_FILL) {
			throw new IOException("Iterated data-block is too big");
		}
		byte[] buffer = new byte[length];
		int pos = 0;
		for (DataBlock block : datablock) {
			pos = block.fillBuffer(buffer, pos);
		}
		return buffer;
	}

	@Override
	public int compareTo(OmfData o) {
		long otherOffset = o.getDataOffset();
		if (dataOffset == otherOffset) {
			return 0;
		}
		return (dataOffset < otherOffset) ? -1 : 1;
	}

	public static class DataBlock {
		private int repeatCount;
		private int blockCount;
		private byte[] simpleBlock = null;
		private DataBlock[] nestedBlock = null;
		
		public static DataBlock read(BinaryReader reader,boolean hasBigFields) throws IOException {
			DataBlock subblock = new DataBlock();
			subblock.repeatCount = OmfRecord.readInt2Or4(reader, hasBigFields);
			subblock.blockCount = reader.readNextShort() & 0xffff;
			if (subblock.blockCount == 0) {
				int size = reader.readNextByte() & 0xff;
				subblock.simpleBlock = new byte[ size ];
				for(int i=0;i<size;++i) {
					subblock.simpleBlock[i] = reader.readNextByte();
				}
			}
			else {
				subblock.nestedBlock = new DataBlock[subblock.blockCount];
				for(int i=0;i<subblock.blockCount;++i) {
					subblock.nestedBlock[i] = read(reader,hasBigFields);		// Recursive definition
				}
			}
			return subblock;
		}

		public int fillBuffer(byte[] buffer, int pos) {
			for (int i = 0; i < repeatCount; ++i) {
				if (simpleBlock != null) {
					for (byte element : simpleBlock) {
						buffer[pos] = element;
						pos += 1;
					}
				}
				else if (nestedBlock != null) {
					for (DataBlock block : nestedBlock) {
						pos = block.fillBuffer(buffer, pos);
					}
				}
			}
			return pos;
		}

		public int getLength() {
			int length = 0;
			if (simpleBlock != null) {
				length = simpleBlock.length;
			}
			else if (nestedBlock != null) {
				for (DataBlock block : nestedBlock) {
					length += block.getLength();
				}
			}
			return length * repeatCount;
		}

		/**
		 * @return true if this DataBlock only represents zero bytes
		 */
		public boolean isAllZeroes() {
			if (simpleBlock != null) {
				for (byte element : simpleBlock) {
					if (element != 0) {
						return false;
					}
				}
			}
			if (nestedBlock != null) {
				for (int i = 0; i < nestedBlock.length; ++i) {
					if (!nestedBlock[i].isAllZeroes()) {
						return false;
					}
				}
			}
			return true;
		}
	}
}
