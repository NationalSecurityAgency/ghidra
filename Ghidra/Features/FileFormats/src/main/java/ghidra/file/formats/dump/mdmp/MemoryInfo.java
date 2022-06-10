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

public class MemoryInfo implements StructConverter {

	public final static String NAME = "MINIDUMP_MEMORY_INFO";

	private long baseAddress;
	private long allocationBase;
	private int allocationProtect;
	private long regionSize;
	private int state;
	private int protect;
	private int type;

	private DumpFileReader reader;
	private long index;

	MemoryInfo(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setBaseAddress(reader.readNextLong());
		setAllocationBase(reader.readNextLong());
		setAllocationProtect(reader.readNextInt());
		reader.readNextInt();
		setRegionSize(reader.readNextLong());
		setState(reader.readNextInt());
		setProtect(reader.readNextInt());
		setType(reader.readNextInt());
		reader.readNextInt();

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "BaseAddress", null);
		struct.add(QWORD, 8, "AllocationBase", null);
		struct.add(DWORD, 4, "AllocationProtect", null);
		struct.add(DWORD, 4, "__alignment1", null);
		struct.add(QWORD, 8, "RegionSize", null);
		struct.add(DWORD, 4, "State", null);
		struct.add(DWORD, 4, "Protect", null);
		struct.add(DWORD, 4, "Type", null);
		struct.add(DWORD, 4, "__alignment2", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public long getBaseAddress() {
		return baseAddress;
	}

	public void setBaseAddress(long baseAddress) {
		this.baseAddress = baseAddress;
	}

	public long getAllocationBase() {
		return allocationBase;
	}

	public void setAllocationBase(long allocationBase) {
		this.allocationBase = allocationBase;
	}

	public int getAllocationProtect() {
		return allocationProtect;
	}

	public void setAllocationProtect(int allocationProtect) {
		this.allocationProtect = allocationProtect;
	}

	public long getRegionSize() {
		return regionSize;
	}

	public void setRegionSize(long regionSize) {
		this.regionSize = regionSize;
	}

	public int getState() {
		return state;
	}

	public void setState(int state) {
		this.state = state;
	}

	public int getProtect() {
		return protect;
	}

	public void setProtect(int protect) {
		this.protect = protect;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}

	public String getComment() {
		String comment = "";
		if ((state & 0x1000) > 0) {
			comment += "COMMIT ";
		}
		if ((state & 0x10000) > 0) {
			comment += "FREE ";
		}
		if ((state & 0x2000) > 0) {
			comment += "RESERVE ";
		}
		if ((type & 0x1000000) > 0) {
			comment += "IMAGE ";
		}
		if ((type & 0x40000) > 0) {
			comment += "MAPPED ";
		}
		if ((type & 0x20000) > 0) {
			comment += "PRIVATE ";
		}
		return comment;
	}
}
