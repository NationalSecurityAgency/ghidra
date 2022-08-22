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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.fbpk.FBPK_Constants;
import ghidra.file.formats.android.fbpk.FBPK_Partition;
import ghidra.file.formats.android.fbpk.FBPT;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class FBPKv1_Partition extends FBPK_Partition {

	private int dataSize;
	private int unknown1;
	private int offsetToNextPartitionTable;
	private int unknown2;
	private FBPTv1 fbpt;
	private long dataStartOffset;

	public FBPKv1_Partition(BinaryReader reader) throws IOException {
		long start = reader.getPointerIndex();

		type = reader.readNextInt();
		name = reader.readNextAsciiString(FBPK_Constants.NAME_MAX_LENGTH);
		dataSize = reader.readNextInt();
		unknown1 = reader.readNextInt();
		offsetToNextPartitionTable = reader.readNextInt();
		unknown2 = reader.readNextInt();

		headerSize = (int) (reader.getPointerIndex() - start);

		if (type == FBPK_Constants.PARTITION_TYPE_DIRECTORY) {
			fbpt = new FBPTv1(reader);
		}
		else if (type == FBPK_Constants.PARTITION_TYPE_FILE) {
			dataStartOffset = reader.getPointerIndex();
		}
	}

	/**
	 * Returns the FBPT.
	 * Could be null if this partition is a FILE.
	 * @return the FBPT
	 */
	public FBPT getFBPT() {
		return fbpt;
	}

	@Override
	public long getDataStartOffset() {
		return dataStartOffset;
	}

	@Override
	public int getDataSize() {
		return dataSize;
	}

	public int getOffsetToNextPartitionTable() {
		return offsetToNextPartitionTable;
	}

	public boolean isDirectory() {
		return getType() == FBPK_Constants.PARTITION_TYPE_DIRECTORY;
	}

	@Override
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
	public void markup(Program program, Address address, TaskMonitor monitor, MessageLog log) throws Exception {

		super.markup(program, address, monitor, log);

		if (isDirectory()) {
			if (fbpt != null) {
				fbpt.processFBPT(program, address.add(headerSize), monitor, log);
			}
		}
		else if (isFile()) {
			//unused, but leave as placeholder for future
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPKv1_Partition.class.getSimpleName(), 0);
		struct.add(DWORD, "type", null);
		struct.add(STRING, FBPK_Constants.NAME_MAX_LENGTH, "name", null);
		struct.add(DWORD, "dataSize", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "offsetToNextPartitionTable", null);
		struct.add(DWORD, "unknown2", null);
		return struct;
	}
}
