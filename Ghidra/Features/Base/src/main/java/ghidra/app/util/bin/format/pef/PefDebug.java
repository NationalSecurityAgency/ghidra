/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;

public class PefDebug implements StructConverter {
	public final static int SIZEOF = 0x12;

	private int unknown;
	private int type;
	private int flags;
	private int distance;
	private int nameLength;
	private String name;

	public PefDebug(Memory memory, Address address) throws MemoryAccessException {
		unknown = memory.getInt(address);
		type = memory.getInt(address.add(0x4));
		flags = memory.getInt(address.add(0x8));
		distance = memory.getInt(address.add(0xc));
		nameLength = memory.getShort(address.add(0x10)) & 0xffff;
		byte [] stringBytes = new byte[nameLength];
		memory.getBytes(address.add(0x12), stringBytes);
		name = new String(stringBytes);
	}

	public int getUnknown() {
		return unknown;
	}
	public int getType() {
		return type;
	}
	public int getFlags() {
		return flags;
	}
	public int getDistance() {
		return distance;
	}
	public int getNameLength() {
		return nameLength;
	}
	public String getName() {
		return name;
	}

	public boolean isValid() {
		if (unknown != 0) {//this field is always zero...?
			return false;
		}
		if (type == 0) {
			return false;
		}
		/*
		if (flags == 0) {
			return false;
		}
		*/
		if (distance > 0xffff) {
			return false;
		}
		if (nameLength <= 0 || nameLength > 255) {
			return false;
		}
		return true;
	}

	public DataType toDataType() throws DuplicateNameException {
		String structureName = "PEF_Debug_0x"+Integer.toHexString(nameLength);
		StructureDataType structure = new StructureDataType(structureName, 0);
		structure.add(new DWordDataType(), "unknown", "");
		structure.add(new DWordDataType(), "type", "");
		structure.add(new DWordDataType(), "flags", "");
		structure.add(new DWordDataType(), "distance", "");
		structure.add(new PascalStringDataType(), nameLength+2, "name", "");
		return structure;
	}
}
