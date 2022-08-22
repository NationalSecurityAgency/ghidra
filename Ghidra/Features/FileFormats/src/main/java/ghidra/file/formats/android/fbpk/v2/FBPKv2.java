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
import ghidra.file.formats.android.fbpk.FBPK;
import ghidra.file.formats.android.fbpk.FBPK_Constants;
import ghidra.file.formats.android.fbpk.FBPK_Partition;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class FBPKv2 implements FBPK {
	private int magic;
	private int version;
	private int unknown1;
	private int unknown2;
	private String string1;
	private String string2;
	private int unknown3;
	private int partitionCount;
	private int size;

	private List<FBPK_Partition> partitions = new ArrayList<>();

	public FBPKv2(BinaryReader reader) throws IOException {
		magic = reader.readNextInt();
		version = reader.readNextInt();
		unknown1 = reader.readNextInt();
		unknown2 = reader.readNextInt();
		string1 = reader.readNextAsciiString(FBPK_Constants.V2_STRING1_MAX_LENGTH);
		string2 = reader.readNextAsciiString(FBPK_Constants.V2_STRING2_MAX_LENGTH);
		unknown3 = reader.readNextInt();
		partitionCount = reader.readNextInt();
		size = reader.readNextInt();

		for (int i = 0; i < partitionCount; ++i) {
			partitions.add(new FBPKv2_Partition(reader));
		}
	}

	@Override
	public int getMagic() {
		return magic;
	}

	@Override
	public int getVersion() {
		return version;
	}

	public int getPartitionCount() {
		return partitionCount;
	}

	public int getSize() {
		return size;
	}

	@Override
	public List<FBPK_Partition> getPartitions() {
		return new ArrayList<FBPK_Partition>(partitions);
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

	public String getString1() {
		return string1;
	}

	public String getString2() {
		return string2;
	};

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPKv2.class.getSimpleName(), 0);
		struct.add(STRING, FBPK_Constants.FBPK.length(), "magic", null);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "unknown2", null);
		struct.add(STRING, FBPK_Constants.V2_STRING1_MAX_LENGTH, "string1", null);
		struct.add(STRING, FBPK_Constants.V2_STRING2_MAX_LENGTH, "string2", null);
		struct.add(DWORD, "unknown3", null);
		struct.add(DWORD, "partitionCount", null);
		struct.add(DWORD, "size", null);
		return struct;
	}

}
