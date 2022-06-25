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

public class Memory64ListStream implements StructConverter {

	public final static String NAME = "MINIDUMP_MEMORY_RANGE_64_LIST";

	private int numberOfMemoryRanges;
	private long baseRVA;
	private MemoryRange64[] memoryRanges;

	private DumpFileReader reader;
	private long index;

	Memory64ListStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setNumberOfMemoryRanges((int) reader.readNextLong());
		setBaseRVA(reader.readNextLong());
		memoryRanges = new MemoryRange64[numberOfMemoryRanges];
		for (int i = 0; i < numberOfMemoryRanges; i++) {
			setMemoryRange(new MemoryRange64(reader, reader.getPointerIndex()), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "NumberOfMemoryRanges", null);
		struct.add(POINTER, 8, "BaseRva", null);
		DataType t = memoryRanges[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, numberOfMemoryRanges, t.getLength());
		struct.add(a, a.getLength(), "MemoryRanges", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public long getNumberOfMemoryRanges() {
		return numberOfMemoryRanges;
	}

	public void setNumberOfMemoryRanges(int numberOfMemoryRanges) {
		this.numberOfMemoryRanges = numberOfMemoryRanges;
	}

	public void setBaseRVA(long baseRVA) {
		this.baseRVA = baseRVA;
	}

	public long getBaseRVA() {
		return baseRVA;
	}

	public MemoryRange64 getMemoryRange(int idx) {
		return memoryRanges[idx];
	}

	public void setMemoryRange(MemoryRange64 memoryRange, int index) {
		this.memoryRanges[index] = memoryRange;
	}

}
