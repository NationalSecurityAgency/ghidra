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
package ghidra.file.formats.dump.pagedump;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class SummaryHeader implements StructConverter {

	public final static String NAME = "PAGEDUMP_SUMMARY";

	public static final int SIGNATURE = 0x45474150;  // "PAGE"

	private int signature;
	private int validDump;
	private int dumpOptions;
	private int headerSize;
	private int bitmapSize;
	private int pages;
	private int sizeOfBitMap;
	private int[] buffer;

	private DumpFileReader reader;
	private long index;

	SummaryHeader(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSignature(reader.readNextInt());
		setValidDump(reader.readNextInt());
		setDumpOptions(reader.readNextInt());
		setHeaderSize(reader.readNextInt());
		setBitmapSize(reader.readNextInt());
		setSizeOfBitMap(reader.readNextInt());
		reader.readNextLong();
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(STRING, 4, "Signature", null);
		struct.add(STRING, 4, "ValidDump", null);
		struct.add(DWORD, 4, "DumpOptions", null);
		struct.add(DWORD, 4, "HeaderSize", null);
		struct.add(DWORD, 4, "BitmapSize", null);
		struct.add(DWORD, 4, "Pages", null);

		StructureDataType s0 = new StructureDataType("RTL_BITMAP", 0);
		s0.add(DWORD, 4, "SizeOfBitMap", null);
		if (sizeOfBitMap > 0) {
			s0.add(QWORD, 8, "", null);
			ArrayDataType a = new ArrayDataType(BYTE, sizeOfBitMap, 1);
			s0.add(a, a.getLength(), "Buffer", null);
		}
		struct.add(s0, s0.getLength(), "BitMap", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public int getSignature() {
		return signature;
	}

	public void setSignature(int signature) {
		this.signature = signature;
	}

	public int getValidDump() {
		return validDump;
	}

	public void setValidDump(int validDump) {
		this.validDump = validDump;
	}

	public int getDumpOptions() {
		return dumpOptions;
	}

	public void setDumpOptions(int dumpOptions) {
		this.dumpOptions = dumpOptions;
	}

	public int getHeaderSize() {
		return headerSize;
	}

	public void setHeaderSize(int headerSize) {
		this.headerSize = headerSize;
	}

	public int getBitmapSize() {
		return bitmapSize;
	}

	public void setBitmapSize(int bitmapSize) {
		this.bitmapSize = bitmapSize;
	}

	public int getPages() {
		return pages;
	}

	public void setPages(int pages) {
		this.pages = pages;
	}

	public int getSizeOfBitMap() {
		return sizeOfBitMap;
	}

	public void setSizeOfBitMap(int sizeOfBitMap) {
		this.sizeOfBitMap = sizeOfBitMap;
	}

	public int[] getBuffer() {
		return buffer;
	}

	public void setBuffer(int[] buffer) {
		this.buffer = buffer;
	}

}
