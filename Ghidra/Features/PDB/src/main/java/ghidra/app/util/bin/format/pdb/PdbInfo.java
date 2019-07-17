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
package ghidra.app.util.bin.format.pdb;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.debug.DebugCodeViewConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class PdbInfo implements PdbInfoIface {
	public final static int MAGIC = 
					DebugCodeViewConstants.SIGNATURE_NB << 16 |
					DebugCodeViewConstants.VERSION_10;

	public static boolean isMatch(BinaryReader reader, int ptr) throws IOException {
		//read value out as big endian
		int value = reader.readByte(ptr  ) << 24 |
					reader.readByte(ptr+1) << 16 |
					reader.readByte(ptr+2) << 8 |
					reader.readByte(ptr+3);
		return MAGIC == value;
	}

	private byte [] magic;
	private int     offset;
	private int     sig;
	private int     age;
	private String  pdbName;

	public PdbInfo(BinaryReader reader, int ptr) throws IOException {
		long origIndex = reader.getPointerIndex();
		reader.setPointerIndex(ptr);
		try {
			magic     = reader.readNextByteArray(4);
			offset    = reader.readNextInt();
			sig       = reader.readNextInt();
			age       = reader.readNextInt();
			pdbName   = reader.readNextAsciiString();
		}
		finally {
			reader.setPointerIndex(origIndex);
		}
	}

	public byte [] getMagic() {
		return magic;
	}

	public int getOffset() {
		return offset;
	}

	public int getSig() {
		return sig;
	}

	public int getAge() {
		return age;
	}

	public String getPdbName() {
		return pdbName;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("PdbInfo", 0);
		struct.add(new StringDataType(), magic.length, "signature", null);
		struct.add(new DWordDataType(), "offset", null);
		struct.add(new DWordDataType(), "sig", null);
		struct.add(new DWordDataType(), "age", null);
		struct.add(new StringDataType(), pdbName.length(), "pdbname", null);
		struct.setCategoryPath(new CategoryPath("/PDB"));
		return struct;
	}
}
