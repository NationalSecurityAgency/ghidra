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
package ghidra.file.formats.android.fbpk.v2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.fbpk.FBPK_Constants;
import ghidra.file.formats.android.fbpk.FBPT_Entry;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class FBPTv2_Entry extends FBPT_Entry {
	private String name;
	private String guid1;
	private String guid2;
	private String format;
	private int unknown1;
	private int unknown2;
	private int unknown3;
	private boolean isLast;

	public FBPTv2_Entry(BinaryReader reader, boolean isLast) throws IOException {
		this.isLast = isLast;
		name = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH);//not +1
		guid1 = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH + 1);
		guid2 = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH + 1);
		format = reader.readNextAsciiString(FBPK_Constants.V2_FORMAT_MAX_LENGTH);
		unknown1 = reader.readNextInt();
		unknown2 = reader.readNextInt();
		unknown3 = reader.readNextInt();
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

	public String getFormat() {
		return format;
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

	public boolean isLast() {
		return isLast;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPTv2_Entry.class.getSimpleName(), 0);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH, "name", null);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH + 1, "guid1", null);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH + 1, "guid2", null);
		struct.add(STRING, FBPK_Constants.V2_FORMAT_MAX_LENGTH, "format", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "unknown2", null);
		struct.add(DWORD, "unknown3", null);
		return struct;
	}

}
