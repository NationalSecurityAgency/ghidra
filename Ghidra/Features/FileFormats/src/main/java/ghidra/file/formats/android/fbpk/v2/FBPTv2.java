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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.fbpk.FBPK_Constants;
import ghidra.file.formats.android.fbpk.FBPT;
import ghidra.file.formats.android.fbpk.FBPT_Entry;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class FBPTv2 extends FBPT {
	private String magic;
	private int nEntries;
	private String guid;

	private List<FBPT_Entry> entries = new ArrayList<>();

	public FBPTv2(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(FBPK_Constants.FBPT.length());
		reader.readNextInt();//unknown0
		reader.readNextInt();//unknown1
		reader.readNextInt();//unknown2
		nEntries = reader.readNextInt();
		guid = reader.readNextAsciiString(FBPK_Constants.V2_GUID_MAX_LENGTH);
		reader.readNextInt();//unknown3
		reader.readNextInt();//unknown4
		reader.readNextInt();//unknown5

		for (int i = 0; i < nEntries; ++i) {
			entries.add(new FBPTv2_Entry(reader, i == nEntries - 1));
		}
	}

	@Override
	public String getMagic() {
		return magic;
	}

	public int getNEntries() {
		return nEntries;
	}

	@Override
	public List<FBPT_Entry> getEntries() {
		return entries;
	}

	public String getGUID() {
		return guid;
	}


	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPTv2.class.getSimpleName(), 0);
		struct.add(STRING, FBPK_Constants.FBPT.length(), "magic", null);
		struct.add(DWORD, "unknown0", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "unknown2", null);
		struct.add(DWORD, "nEntries", null);
		struct.add(STRING, FBPK_Constants.V2_GUID_MAX_LENGTH, "guid", null);
		struct.add(DWORD, "unknown3", null);
		struct.add(DWORD, "unknown4", null);
		struct.add(DWORD, "unknown5", null);
		return struct;
	}

}
