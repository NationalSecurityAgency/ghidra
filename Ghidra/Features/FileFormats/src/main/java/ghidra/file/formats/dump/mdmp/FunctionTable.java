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

public class FunctionTable implements StructConverter {

	public final static String NAME = "MINIDUMP_FUNCTION_TABLE";

	private long minimumAddress;
	private long maximumAddress;
	private long baseAddress;
	private int entryCount;
	private int sizeOfAlignPad;

	private DumpFileReader reader;
	private long index;

	FunctionTable(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setMinimumAddress(reader.readNextLong());
		setMaximumAddress(reader.readNextLong());
		setBaseAddress(reader.readNextLong());
		setEntryCount(reader.readNextInt());
		setSizeOfAlignPad(reader.readNextInt());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "MinimumAddress", null);
		struct.add(QWORD, 8, "MaximumAddress", null);
		struct.add(QWORD, 8, "BaseAddress", null);
		struct.add(DWORD, 4, "EntryCount", null);
		struct.add(DWORD, 4, "SizeOfAlignPad", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public long getMinimumAddress() {
		return minimumAddress;
	}

	public void setMinimumAddress(long minimumAddress) {
		this.minimumAddress = minimumAddress;
	}

	public long getMaximumAddress() {
		return maximumAddress;
	}

	public void setMaximumAddress(long maximumAddress) {
		this.maximumAddress = maximumAddress;
	}

	public long getBaseAddress() {
		return baseAddress;
	}

	public void setBaseAddress(long baseAddress) {
		this.baseAddress = baseAddress;
	}

	public int getEntryCount() {
		return entryCount;
	}

	public void setEntryCount(int entryCount) {
		this.entryCount = entryCount;
	}

	public int getSizeOfAlignPad() {
		return sizeOfAlignPad;
	}

	public void setSizeOfAlignPad(int sizeOfAlignPad) {
		this.sizeOfAlignPad = sizeOfAlignPad;
	}

}
