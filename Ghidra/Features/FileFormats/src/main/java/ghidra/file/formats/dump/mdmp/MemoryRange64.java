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

public class MemoryRange64 implements StructConverter {

	public final static String NAME = "MINIDUMP_MEMORY_RANGE_64";

	private long startOfMemoryRange;
	private long dataSize;

	// MemoryRange64 is used for full-memory minidumps where
	// all of the raw memory is laid out sequentially at the
	// end of the dump.  There is no need for individual RVAs
	// as the RVA is the base RVA plus the sum of the preceeding
	// data blocks.

	private DumpFileReader reader;
	private long index;

	MemoryRange64(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setStartOfMemoryRange(reader.readNextLong());
		setDataSize(reader.readNextLong());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "StartOfMemoryRange", null);
		struct.add(QWORD, 8, "DataSize", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public long getStartOfMemoryRange() {
		return startOfMemoryRange;
	}

	public void setStartOfMemoryRange(long startOfMemoryRange) {
		this.startOfMemoryRange = startOfMemoryRange;
	}

	public long getDataSize() {
		return dataSize;
	}

	public void setDataSize(long dataSize) {
		this.dataSize = dataSize;
	}

}
