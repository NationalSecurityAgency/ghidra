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

public class UnloadedDriver implements StructConverter {

	public final static String NAME = "_DUMP_UNLOADED_DRIVERS";

	private int nameLength;
	private String name;
	private long startAddress;
	private long endAddress;

	private DumpFileReader reader;
	private long index;
	private int psz;

	UnloadedDriver(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setNameLength(reader.readNextShort());
		reader.readNextShort();
		reader.readNextInt();
		reader.readNextPointer();
		setName(reader.readNextUnicodeString(12));
		setStartAddress(reader.readNextPointer());
		setEndAddress(reader.readNextPointer());
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(WORD, 2, "NameLength", null);
		struct.add(WORD, 2, "", null);
		struct.add(DWORD, 4, "", null);
		struct.add(POINTER, psz, "", null);
		struct.add(UTF16, 24, "Name", null);
		struct.add(POINTER, psz, "StartAddress", null);
		struct.add(POINTER, psz, "EndAddress", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public int getNameLength() {
		return nameLength;
	}

	public void setNameLength(int nameLength) {
		this.nameLength = nameLength;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public long getStartAddress() {
		return startAddress;
	}

	public void setStartAddress(long startAddress) {
		this.startAddress = startAddress;
	}

	public long getEndAddress() {
		return endAddress;
	}

	public void setEndAddress(long endAddress) {
		this.endAddress = endAddress;
	}

	public long getSize() {
		long len = endAddress - startAddress;
		return (len < 0) ? -len : len;
	}

}
