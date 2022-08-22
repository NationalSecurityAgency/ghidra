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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class MemoryInfoListStream implements StructConverter {

	public final static String NAME = "MINIDUMP_MEMORY_INFO_LIST";

	private int sizeOfHeader;
	private int sizeOfEntry;
	private int numberOfEntries;
	private MemoryInfo[] memoryInfo;

	private DumpFileReader reader;
	private long index;

	MemoryInfoListStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSizeOfHeader(reader.readNextInt());
		setSizeOfEntry(reader.readNextInt());
		setNumberOfEntries((int) reader.readNextLong());
		memoryInfo = new MemoryInfo[numberOfEntries];
		for (int i = 0; i < numberOfEntries; i++) {
			setMemoryInfo(new MemoryInfo(reader, reader.getPointerIndex()), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "SizeOfHeader", null);
		struct.add(DWORD, 4, "SizeOfEntry", null);
		struct.add(QWORD, 8, "NumberOfMemoryRanges", null);
		DataType t = memoryInfo[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, numberOfEntries, t.getLength());
		struct.add(a, a.getLength(), "MemoryRanges", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public void setSizeOfHeader(int sizeOfHeader) {
		this.sizeOfHeader = sizeOfHeader;
	}

	public int getSizeOfHeader() {
		return sizeOfHeader;
	}

	public void setSizeOfEntry(int sizeOfEntry) {
		this.sizeOfEntry = sizeOfEntry;
	}

	public int getSizeOfEntry() {
		return sizeOfEntry;
	}

	public void setNumberOfEntries(int numberOfEntries) {
		this.numberOfEntries = numberOfEntries;
	}

	public long getNumberOfEntries() {
		return numberOfEntries;
	}

	public MemoryInfo getMemoryInfo(int idx) {
		return memoryInfo[idx];
	}

	public void setMemoryInfo(MemoryInfo memoryInfo, int index) {
		this.memoryInfo[index] = memoryInfo;
	}

}
