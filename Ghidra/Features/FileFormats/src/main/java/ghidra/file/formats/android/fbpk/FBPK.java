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

public class FBPK implements StructConverter {
	private String magic;
	private int unknown1;
	private String version;
	private int partitionCount;
	private int size;
	private List<FBPK_Partition> partitions = new ArrayList<>();

	public FBPK(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(FBPK_Constants.FBPK.length());
		unknown1 = reader.readNextInt();
		version = reader.readNextAsciiString(FBPK_Constants.VERSION_MAX_LENGTH);
		partitionCount = reader.readNextInt();
		size = reader.readNextInt();

		for (int i = 0; i < partitionCount; ++i) {
			FBPK_Partition partition = new FBPK_Partition(reader);
			partitions.add(partition);
			reader.setPointerIndex(partition.getOffsetToNextPartitionTable());
		}
	}

	public String getMagic() {
		return magic;
	}

	public String getVersion() {
		return version;
	}

	public int getPartitionCount() {
		return partitionCount;
	}

	public int getSize() {
		return size;
	}

	public List<FBPK_Partition> getPartitions() {
		return partitions;
	}

	public int getUnknown1() {
		return unknown1;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(FBPK.class);
		Structure struct = new StructureDataType(className, 0);
		struct.add(STRING, FBPK_Constants.FBPK.length(), "magic", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(STRING, FBPK_Constants.VERSION_MAX_LENGTH, "version", null);
		struct.add(DWORD, "count", null);
		struct.add(DWORD, "size", null);
		return struct;
	}

}
