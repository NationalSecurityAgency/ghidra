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
import ghidra.file.formats.android.fbpk.FBPK;
import ghidra.file.formats.android.fbpk.FBPK_Constants;
import ghidra.file.formats.android.fbpk.FBPK_Partition;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class FBPKv1 implements FBPK {
	private int magic;
	private int version;
	private String string;
	private int partitionCount;
	private int size;
	private List<FBPK_Partition> partitions = new ArrayList<>();

	public FBPKv1(BinaryReader reader) throws IOException {
		magic = reader.readNextInt();
		version = reader.readNextInt();
		string = reader.readNextAsciiString(FBPK_Constants.V1_VERSION_MAX_LENGTH);
		partitionCount = reader.readNextInt();
		size = reader.readNextInt();

		for (int i = 0; i < partitionCount; ++i) {
			FBPKv1_Partition partition = new FBPKv1_Partition(reader);
			partitions.add(partition);
			reader.setPointerIndex(partition.getOffsetToNextPartitionTable());
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

	public String getString() {
		return string;
	}

	public int getPartitionCount() {
		return partitionCount;
	}

	public int getSize() {
		return size;
	}

	@Override
	public List<FBPK_Partition> getPartitions() {
		return partitions;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPKv1.class.getSimpleName(), 0);
		struct.add(STRING, FBPK_Constants.FBPK.length(), "magic", null);
		struct.add(DWORD, "version", null);
		struct.add(STRING, FBPK_Constants.V1_VERSION_MAX_LENGTH, "string", null);
		struct.add(DWORD, "partitionCount", null);
		struct.add(DWORD, "size", null);
		return struct;
	}

}
