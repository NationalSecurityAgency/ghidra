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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.rich.PERichTableDataType;
import ghidra.app.util.bin.format.pe.rich.RichHeaderRecord;
import ghidra.program.model.data.DataType;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Top level object model of the {@link RichHeader}.  Stores an array of
 * {@link RichHeaderRecord}.
 */
public class RichTable {

	private static int MAX_TABLE_SEARCH_COUNT = 100;

	private int mask;
	private long imageOffset;
	private int size;
	private RichHeaderRecord[] records = new RichHeaderRecord[0];

	public RichTable(MemBuffer buf) {
		parse(buf, 0);
	}

	public RichTable(BinaryReader reader) {
		parse(reader, reader.getPointerIndex());
	}

	private void parse(Object src, final long base) {
		boolean valid = false;

		long offset = base;
		long startOffset = offset;
		long endOffset = base;

		int nSignDwords = 0;

		try {

			// Scan forward looking for the Rich signature (or the PE signature, 
			// and we've gone too far) -- this sets the upper-bound (endOffset) of the table 
			for (int i = 0; i < MAX_TABLE_SEARCH_COUNT; i++, offset += 4) {
				int dw = readInt(src, offset);
				if (dw == RichHeader.IMAGE_RICH_SIGNATURE) {
					endOffset = offset + 8;// space for the signature and mask
					break;
				}
				if (dw == Constants.IMAGE_NT_SIGNATURE) {
					break;
				}
			}

			// Ensure we've determined the table-end
			if (endOffset != startOffset) {

				// The table mask follows; read it next
				offset += 4;
				mask = readInt(src, offset);

				// Now scan backwards until we find the DanS signature -- the lower-bound
				// of the table (startOffset);
				long _scanOffset = offset - 8;
				for (int i = 0; i < MAX_TABLE_SEARCH_COUNT; i--) {
					int dw = readInt(src, _scanOffset);
					if ((dw ^ mask) == RichHeader.IMAGE_DANS_SIGNATURE) {
						startOffset = (int) _scanOffset;
						nSignDwords++;
						valid = true;
						break;
					}
					_scanOffset -= 4;
					nSignDwords++;

					if (_scanOffset < base) {
						break;
					}
				}

				if (valid) {
					// Now that we know the bounds of the table, verify the padding bytes 
					offset = startOffset + 4;
					for (int i = 0; i < 3; i++, offset += 4) {
						int v = readInt(src, offset);
						if ((v ^ mask) != 0) {
							valid = false;
							break;
						}
					}
				}
			}

		}
		catch (IOException ioe) {
			valid = false;
		}

		if (!valid) {
			this.mask = -1;
			this.imageOffset = -1;
			this.size = 0;
			return;
		}

		// nSignDwords includes the 4 dwords of the header (DanS & padding dwords)...
		int numRecords = (nSignDwords / 2) - 2;

		this.imageOffset = startOffset;
		this.size = (int) (endOffset - imageOffset);

		records = new RichHeaderRecord[numRecords];

		offset = imageOffset + 16;// skip the DanS signature and padding dwords

		try {
			for (int i = 0; i < numRecords; i++) {

				int data1 = readInt(src, offset);
				int data2 = readInt(src, offset + 4);
				offset += 8;

				data1 ^= mask;
				data2 ^= mask;

				RichHeaderRecord rec = new RichHeaderRecord(i, data1, data2);

				records[i] = rec;
			}
		}
		catch (IOException ioe) {
			valid = false;
		}

		if (!valid) {
			records = new RichHeaderRecord[0];
			this.mask = -1;
			this.imageOffset = -1;
			this.size = 0;
			return;
		}

	}

	private static int readInt(Object src, long offset) throws IOException {
		if (src instanceof MemBuffer) {
			return readInt((MemBuffer) src, offset);
		}
		else if (src instanceof BinaryReader) {
			return readInt((BinaryReader) src, offset);
		}
		throw new IOException("Source must be a MemBuffer or BinaryReader");
	}

	private static int readInt(MemBuffer buf, long offset) throws IOException {
		try {
			return buf.getInt((int) offset) & 0xFFFFFFFF;
		}
		catch (MemoryAccessException mae) {
			throw new IOException(mae);
		}
	}

	private static int readInt(BinaryReader reader, long offset) throws IOException {
		return reader.readInt(offset) & 0xFFFFFFFF;
	}

	public RichHeaderRecord[] getRecords() {
		return records;
	}

	public long getOffset() {
		return imageOffset;
	}

	public int getMask() {
		return mask;
	}

	public int getSize() {
		return size;
	}

	@Override
	public String toString() {
		return RichHeader.NAME + "[mask=" + Integer.toHexString(mask) + "h, numRecords=" +
			records.length + "]";
	}

	public DataType toDataType() {
		return new PERichTableDataType();
	}
}
