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
import java.io.RandomAccessFile;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.pe.rich.RichHeaderRecord;
import ghidra.program.model.data.DataType;
import ghidra.util.DataConverter;

/**
 * The "Rich" header contains encoded metadata about the tool chain used to generate the binary.
 * This class decodes and writes the Rich header (if it exists).
 */
public class RichHeader implements StructConverter, Writeable {

	public final static int IMAGE_RICH_SIGNATURE = 0x68636952; // Rich
	public final static int IMAGE_DANS_SIGNATURE = 0x536E6144; // DanS
	public final static String NAME = "IMAGE_RICH_HEADER";

	private BinaryReader reader;
	private RichTable table;

	/**
	 * Creates the Rich header found from the given reader.  The reader should be
	 * positioned directly after the DOS header.
	 * 
	 * @param reader The reader to read the PE with.
	 */
	public RichHeader(BinaryReader reader) {
		this.reader = reader;
		parse();
	}

	private void parse() {

		long currPos = reader.getPointerIndex();

		table = new RichTable(reader);

		if (table.getSize() == 0) {
			reader.setPointerIndex(currPos);
			return;
		}

		reader.setPointerIndex(table.getOffset() + table.getSize());
	}

	/**
	 * Gets the offset of the Rich header.
	 * 
	 * @return the offset of the Rich header, or -1 if a Rich header was not found.
	 */
	public int getOffset() {
		return table == null ? -1 : (int) table.getOffset();
	}

	/**
	 * Gets the size of the Rich header.
	 * 
	 * @return the size of the Rich header.  Will be 0 if a Rich header was not found.
	 */
	public int getSize() {
		return table == null ? 0 : table.getSize();
	}

	/**
	 * Gets the Rich header mask.
	 * 
	 * @return the Rich header mask, or -1 if a Rich header was not found.
	 */
	public int getMask() {
		return table == null ? -1 : table.getMask();
	}

	/**
	 * Gets the Rich header records.
	 * 
	 * @return the Rich header records.  Could be empty if a Rich header was not found.
	 */
	public RichHeaderRecord[] getRecords() {
		return table == null ? new RichHeaderRecord[0] : table.getRecords();
	}

	@Override
	public DataType toDataType() {
		if (table.getSize() == 0) {
			return null;
		}
		return table.toDataType();
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {

		if (table != null) {
			raf.write(dc.getBytes(IMAGE_DANS_SIGNATURE));

			raf.write(dc.getBytes(table.getMask())); // 0 ^ mask
			raf.write(dc.getBytes(table.getMask())); // 0 ^ mask
			raf.write(dc.getBytes(table.getMask())); // 0 ^ mask

			for (RichHeaderRecord rec : table.getRecords()) {
				raf.write(dc.getBytes(rec.getCompId().getValue() ^ table.getMask()));
				raf.write(dc.getBytes(rec.getObjectCount() ^ table.getMask()));
			}

			raf.write(dc.getBytes(IMAGE_RICH_SIGNATURE));
			raf.write(dc.getBytes(table.getMask()));
		}
	}
}
