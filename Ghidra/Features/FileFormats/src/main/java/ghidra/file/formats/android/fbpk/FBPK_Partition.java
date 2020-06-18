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
import ghidra.util.exception.DuplicateNameException;

public class FBPK_Partition implements StructConverter {
	private int type;
	private String name;
	private int dataSize;
	private int unknown1;
	private int offsetToNextPartitionTable;
	private int unknown2;
	private FBPT fbpt;
	private long dataStartOffset;

	public FBPK_Partition(BinaryReader reader) throws IOException {
		type = reader.readNextInt();
		name = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH);
		dataSize = reader.readNextInt();
		unknown1 = reader.readNextInt();
		offsetToNextPartitionTable = reader.readNextInt();
		unknown2 = reader.readNextInt();
		if (type == FBPK_Constants.PARTITION_TYPE_DIRECTORY) {
			fbpt = new FBPT(reader);
		}
		else if (type == FBPK_Constants.PARTITION_TYPE_FILE) {
			dataStartOffset = reader.getPointerIndex();
		}
	}

	public int getType() {
		return type;
	}

	public String getName() {
		return name;
	}

	/**
	 * Returns the Fast Boot Partition Table
	 * @return the Fast Boot Partition Table, could be null if file
	 */
	public FBPT getFBPT() {
		return fbpt;
	}

	public long getDataStartOffset() {
		return dataStartOffset;
	}

	public int getDataSize() {
		return dataSize;
	}

	public int getOffsetToNextPartitionTable() {
		return offsetToNextPartitionTable;
	}

	public boolean isDirectory() {
		return getType() == FBPK_Constants.PARTITION_TYPE_DIRECTORY;
	}

	public boolean isFile() {
		return getType() == FBPK_Constants.PARTITION_TYPE_FILE;
	}

	public int getUnknown1() {
		return unknown1;
	}

	public int getUnknown2() {
		return unknown2;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(FBPK_Partition.class);
		Structure struct = new StructureDataType(className, 0);
		struct.add(DWORD, "type", null);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH, "name", null);
		struct.add(DWORD, "dataSize", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "offsetToNextPartitionTable", null);
		struct.add(DWORD, "unknown2", null);
		return struct;
	}
}
