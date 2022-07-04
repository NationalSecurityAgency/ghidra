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
import java.util.*;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;

public class FullDumpHeader implements StructConverter {

	public final static String NAME = "PAGEDUMP_FULL";

	public static final int SIGNATURE = 0x45474150;  // "PAGE"

	private int signature;
	private int validDump;
	private long dumpOptions;
	private long headerSize;
	private long bitmapSize;
	private long pages;
	private byte[] buffer;
	private Map<Integer, Integer> pfnToRva = new HashMap<>();

	private DumpFileReader reader;
	private long index;

	FullDumpHeader(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSignature(reader.readNextInt());
		setValidDump(reader.readNextInt());
		setDumpOptions(reader.readNextLong());
		reader.readNextLong();
		reader.readNextLong();
		setHeaderSize(reader.readNextLong());
		setBitmapSize(reader.readNextLong());
		setPages(reader.readNextLong());

		buffer = new byte[(int) (pages + 7) / 8];
		int pfn = 0;
		int rvan = 0;
		for (int i = 0; i < buffer.length; i++) {
			buffer[i] = reader.readNextByte();
			short temp = (short) (buffer[i] + 256);
			for (int j = 0; j < 8; j++) {
				int bitval = (temp >> j) % 2;
				if (bitval != 0) {
					pfn = i * 8 + j;
					pfnToRva.put(pfn, rvan++);
				}
			}
		}
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(STRING, 4, "Signature", null);
		struct.add(STRING, 4, "ValidDump", null);
		struct.add(QWORD, 8, "DumpOptions", null);
		struct.add(QWORD, 8, "", null);
		struct.add(QWORD, 8, "", null);
		struct.add(QWORD, 8, "HeaderSize", null);
		struct.add(QWORD, 8, "BitmapSize", null);
		struct.add(QWORD, 8, "Pages", null);

		if (bitmapSize > 0) {
			ArrayDataType a = new ArrayDataType(BYTE, (int) (pages / 8), 1);
			struct.add(a, a.getLength(), "Buffer", null);
		}

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

	public long getDumpOptions() {
		return dumpOptions;
	}

	public void setDumpOptions(long dumpOptions) {
		this.dumpOptions = dumpOptions;
	}

	public long getHeaderSize() {
		return headerSize;
	}

	public void setHeaderSize(long headerSize) {
		this.headerSize = headerSize;
	}

	public long getBitmapSize() {
		return bitmapSize;
	}

	public void setBitmapSize(long bitmapSize) {
		this.bitmapSize = bitmapSize;
	}

	public long getPages() {
		return pages;
	}

	public void setPages(long pages) {
		this.pages = pages;
	}

	public byte[] getBuffer() {
		return buffer;
	}

	public void setBuffer(byte[] buffer) {
		this.buffer = buffer;
	}

	public Integer PFN2RVA(Integer pfn) {
		return pfnToRva.get(pfn);
	}

	public Set<Integer> pfnKeySet() {
		return pfnToRva.keySet();
	}

}
