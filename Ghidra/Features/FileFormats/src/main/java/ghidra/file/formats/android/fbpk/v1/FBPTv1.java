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
package ghidra.file.formats.android.fbpk.v1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.fbpk.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class FBPTv1 extends FBPT {
	private String magic;
	private int nEntries;
	private List<FBPT_Entry> entries = new ArrayList<>();

	public FBPTv1(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(FBPK_Constants.FBPT.length());
		reader.readNextInt();//unknown0
		reader.readNextInt();//unknown1
		reader.readNextInt();//unknown2
		nEntries = reader.readNextInt();
		reader.readNextInt();//unknown3
		reader.readNextInt();//unknown4
		reader.readNextInt();//unknown5
		reader.readNextInt();//unknown6
		reader.readNextInt();//unknown7
		reader.readNextInt();//unknown8
		reader.readNextInt();//unknown9
		reader.readNextInt();//unknownA
		reader.readNextInt();//unknownB
		reader.readNextInt();//unknownC
		reader.readNextInt();//unknownD
		reader.readNextInt();//unknownE
		reader.readNextInt();//unknownF

		for (int i = 0; i < nEntries; ++i) {
			entries.add(new FBPTv1_Entry(reader, i == nEntries - 1));
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

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPTv1.class.getSimpleName(), 0);
		struct.add(STRING, FBPK_Constants.FBPT.length(), "magic", null);
		struct.add(DWORD, "unknown0", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "unknown2", null);
		struct.add(DWORD, "nEntries", null);
		struct.add(DWORD, "unknown3", null);
		struct.add(DWORD, "unknown4", null);
		struct.add(DWORD, "unknown5", null);
		struct.add(DWORD, "unknown6", null);
		struct.add(DWORD, "unknown7", null);
		struct.add(DWORD, "unknown8", null);
		struct.add(DWORD, "unknown9", null);
		struct.add(DWORD, "unknownA", null);
		struct.add(DWORD, "unknownB", null);
		struct.add(DWORD, "unknownC", null);
		struct.add(DWORD, "unknownD", null);
		struct.add(DWORD, "unknownE", null);
		struct.add(DWORD, "unknownF", null);
		return struct;
	}

}
