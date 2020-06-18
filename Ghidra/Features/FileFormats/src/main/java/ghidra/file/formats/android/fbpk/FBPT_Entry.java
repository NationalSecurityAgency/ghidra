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
package ghidra.file.formats.android.fbpk;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

public class FBPT_Entry implements StructConverter {
	private String name;
	private String guid1;
	private String guid2;
	private String padding;
	private int unknown1;
	private int unknown2;
	private int unknown3;
	private boolean isLast;

	public FBPT_Entry(BinaryReader reader, boolean isLast) throws IOException {
		this.isLast = isLast;
		name = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH);//not +1
		guid1 = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH + 1);
		guid2 = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH + 1);
		padding = reader.readNextAsciiString(2);
		if (FBPK_Constants.LAST_PARTITION_ENTRY.equals(name)) {
			return;
		}
		unknown1 = reader.readNextInt();
		if (!isLast) {
			unknown2 = reader.readNextInt();
			unknown3 = reader.readNextInt();
		}
	}

	public String getName() {
		return name;
	}

	public String getGuid1() {
		return guid1;
	}

	public String getGuid2() {
		return guid2;
	}

	public String getPadding() {
		return padding;
	}

	public int getUnknown1() {
		return unknown1;
	}

	public int getUnknown2() {
		return unknown2;
	}

	public int getUnknown3() {
		return unknown3;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(FBPT_Entry.class);
		Structure struct = new StructureDataType(className, 0);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH, "name", null);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH + 1, "guid1", null);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH + 1, "guid2", null);
		struct.add(STRING, 2, "padding", null);
		if (FBPK_Constants.LAST_PARTITION_ENTRY.equals(name) || isLast) {
			try {
				struct.setName(className + "_last");
			}
			catch (InvalidNameException e) {
				//ignore
			}
		}
		else {
			struct.add(DWORD, "unknown1", null);
			if (!isLast) {
				struct.add(DWORD, "unknown2", null);
				struct.add(DWORD, "unknown3", null);
			}
		}
		return struct;
	}

}
