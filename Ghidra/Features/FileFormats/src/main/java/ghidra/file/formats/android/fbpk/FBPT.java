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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class FBPT implements StructConverter {
	private String magic;
	private int unknown1;
	private int unknown2;
	private int unknown3;
	private int nEntries;
	private int unknownA;
	private int unknownB;
	private int unknownC;
	private int unknownD;
	private int unknownE;
	private int unknownF;
	private int unknownG;
	private int unknownH;
	private int unknownI;
	private int unknownJ;
	private int unknownK;
	private int unknownL;
	private int unknownM;
	private List<FBPT_Entry> entries = new ArrayList<>();

	public FBPT(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(FBPK_Constants.FBPT.length());
		unknown1 = reader.readNextInt();
		unknown2 = reader.readNextInt();
		unknown3 = reader.readNextInt();
		nEntries = reader.readNextInt();
		unknownA = reader.readNextInt();
		unknownB = reader.readNextInt();
		unknownC = reader.readNextInt();
		unknownD = reader.readNextInt();
		unknownE = reader.readNextInt();
		unknownF = reader.readNextInt();
		unknownG = reader.readNextInt();
		unknownH = reader.readNextInt();
		unknownI = reader.readNextInt();
		unknownJ = reader.readNextInt();
		unknownK = reader.readNextInt();
		unknownL = reader.readNextInt();
		unknownM = reader.readNextInt();

		for (int i = 0; i < nEntries; ++i) {
			entries.add(new FBPT_Entry(reader, i == nEntries - 1));
		}
	}

	public String getMagic() {
		return magic;
	}

	public int getNEntries() {
		return nEntries;
	}

	public List<FBPT_Entry> getEntries() {
		return entries;
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

	public int getUnknownA() {
		return unknownA;
	}

	public int getUnknownB() {
		return unknownB;
	}

	public int getUnknownC() {
		return unknownC;
	}

	public int getUnknownD() {
		return unknownD;
	}

	public int getUnknownE() {
		return unknownE;
	}

	public int getUnknownF() {
		return unknownF;
	}

	public int getUnknownG() {
		return unknownG;
	}

	public int getUnknownH() {
		return unknownH;
	}

	public int getUnknownI() {
		return unknownI;
	}

	public int getUnknownJ() {
		return unknownJ;
	}

	public int getUnknownK() {
		return unknownK;
	}

	public int getUnknownL() {
		return unknownL;
	}

	public int getUnknownM() {
		return unknownM;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(FBPT.class);
		Structure struct = new StructureDataType(className, 0);
		struct.add(STRING, FBPK_Constants.FBPT.length(), "magic", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "unknown2", null);
		struct.add(DWORD, "unknown3", null);
		struct.add(DWORD, "nEntries", null);
		struct.add(DWORD, "unknownA", null);
		struct.add(DWORD, "unknownB", null);
		struct.add(DWORD, "unknownC", null);
		struct.add(DWORD, "unknownD", null);
		struct.add(DWORD, "unknownE", null);
		struct.add(DWORD, "unknownF", null);
		struct.add(DWORD, "unknownG", null);
		struct.add(DWORD, "unknownH", null);
		struct.add(DWORD, "unknownI", null);
		struct.add(DWORD, "unknownJ", null);
		struct.add(DWORD, "unknownK", null);
		struct.add(DWORD, "unknownL", null);
		struct.add(DWORD, "unknownM", null);
		return struct;
	}

}
