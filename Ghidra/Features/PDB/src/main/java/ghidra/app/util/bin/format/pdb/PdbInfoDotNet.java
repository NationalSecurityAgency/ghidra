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
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.app.util.datatype.microsoft.GuidDataType;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class PdbInfoDotNet implements PdbInfoDotNetIface {
	public final static int MAGIC = DebugCodeViewConstants.SIGNATURE_DOT_NET << 16 |
		DebugCodeViewConstants.VERSION_DOT_NET;

	public static boolean isMatch(BinaryReader reader, int ptr) throws IOException {
		//read value out as big endian
		int value =
			reader.readByte(ptr) << 24 | reader.readByte(ptr + 1) << 16 |
				reader.readByte(ptr + 2) << 8 | reader.readByte(ptr + 3);
		return MAGIC == value;
	}

	private byte[] magic;
	private GUID guid;
	private int age;
	private String pdbName;

	public PdbInfoDotNet(BinaryReader reader, int ptr) throws IOException {
		long origIndex = reader.getPointerIndex();
		reader.setPointerIndex(ptr);
		try {
			magic = reader.readNextByteArray(4);
			guid = new GUID(reader);
			age = reader.readNextInt();
			pdbName = reader.readNextAsciiString();
		}
		finally {
			reader.setPointerIndex(origIndex);
		}
	}

	public String getPdbName() {
		return pdbName;
	}

	public int getAge() {
		return age;
	}

	public int getSignature() {
		return guid.getData1();
	}

	public GUID getGUID() {
		return guid;
	}

	public byte[] getMagic() {
		return magic;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("DotNetPdbInfo", 0);
		struct.add(new StringDataType(), magic.length, "signature", null);
		struct.add(new GuidDataType(), "guid", null);
		struct.add(new DWordDataType(), "age", null);
		if (pdbName.length() > 0) {
			struct.add(new StringDataType(), pdbName.length(), "pdbname", null);
		}
		struct.setCategoryPath(new CategoryPath("/PDB"));
		return struct;
	}
}
