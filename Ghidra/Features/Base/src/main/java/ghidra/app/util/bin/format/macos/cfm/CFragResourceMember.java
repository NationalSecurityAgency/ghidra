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
package ghidra.app.util.bin.format.macos.cfm;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class CFragResourceMember implements StructConverter {
	public final static int kNullCFragVersion     =  0;
	public final static int kWildcardCFragVersion = -1;

	private String             architecture;
	private short              reservedA;//must be zero
	private byte               reservedB;//must be zero
	private byte               updateLevel;
	private int                currentVersion;
	private int                oldDefVersion;
	private CFragUsage1Union   uUsage1;
	private CFragUsage2Union   uUsage2;
	private CFragUsage         usage;
	private CFragLocatorKind   where;
	private int                offset;
	private int                length;
	private CFragWhere1Union   uWhere1;
	private CFragWhere2Union   uWhere2;
	private short              extensionCount;
	private short              memberSize;//total size in bytes
	private String             name;

	public CFragResourceMember(BinaryReader reader) throws IOException {
		architecture     = reader.readNextAsciiString(4);
		reservedA        = reader.readNextShort();
		reservedB        = reader.readNextByte();
		updateLevel      = reader.readNextByte();
		currentVersion   = reader.readNextInt();
		oldDefVersion    = reader.readNextInt();
		uUsage1          = new CFragUsage1Union(reader);
		uUsage2          = new CFragUsage2Union(reader);
		usage            = CFragUsage.get(reader);
		where            = CFragLocatorKind.get(reader);
		offset           = reader.readNextInt();
		length           = reader.readNextInt();
		uWhere1          = new CFragWhere1Union(reader);
		uWhere2          = new CFragWhere2Union(reader);
		extensionCount   = reader.readNextShort();
		memberSize       = reader.readNextShort();

		int nameLength   = reader.readNextByte() & 0xff;
		name             = reader.readNextAsciiString(nameLength);

		if (reservedA != 0 ||
			reservedB != 0) {
			throw new IOException("Reserved fields contain invalid value(s).");
		}
	}

	public String getArchitecture() {
		return architecture;
	}

	public byte getUpdateLevel() {
		return updateLevel;
	}

	public int getCurrentVersion() {
		return currentVersion;
	}

	public int getOldDefVersion() {
		return oldDefVersion;
	}

	public CFragUsage1Union getUUsage1() {
		return uUsage1;
	}

	public CFragUsage2Union getUUsage2() {
		return uUsage2;
	}

	public CFragUsage getUsage() {
		return usage;
	}

	public CFragLocatorKind getWhere() {
		return where;
	}

	public int getOffset() {
		return offset;
	}

	public int getLength() {
		return length;
	}

	public CFragWhere1Union getUWhere1() {
		return uWhere1;
	}

	public CFragWhere2Union getUWhere2() {
		return uWhere2;
	}

	public int getExtensionCount() {
		return extensionCount;
	}

	public int getMemberSize() {
		return memberSize;
	}

	public String getName() {
		return name;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String structName = StructConverterUtil.parseName(CFragResourceMember.class);
		Structure struct = new StructureDataType(structName, 0);
		struct.add(STRING, 4, "architecture", null);
		struct.add(WORD, "reservedA", null);
		struct.add(BYTE, "reservedB", null);
		struct.add(BYTE, "updateLevel", null);
		struct.add(DWORD, "currentVersion", null);
		struct.add(DWORD, "oldDefVersion", null);
		struct.add(DWORD, "usage", usage.toString());
		struct.add(DWORD, "where", where.toString());
		struct.add(DWORD, "offset", null);
		struct.add(DWORD, "length", null);
		struct.add(BYTE, "reservedC", null);
		struct.add(BYTE, "reservedD", null);
		struct.add(DWORD, "extensionCount", null);
		struct.add(DWORD, "memberSize", null);
		struct.add(new PascalString255DataType(), name.length()+1, "name", null);
		return struct;
	}
}
