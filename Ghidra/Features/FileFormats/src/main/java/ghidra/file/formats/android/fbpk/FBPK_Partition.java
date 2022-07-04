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

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;

public abstract class FBPK_Partition implements StructConverter {

	protected int headerSize;
	protected int type;
	protected String name;
	protected int partitionIndex;

	/**
	 * Returns the size of the partition's header, in bytes.
	 * @return the size of the partition's header, in bytes
	 */
	public final int getHeaderSize() {
		return headerSize;
	}

	/**
	 * Returns the partition's type.
	 * @return the partition's type
	 */
	public final int getType() {
		return type;
	}

	/**
	 * Returns the partition's name.
	 * @return the partition's name
	 */
	public final String getName() {
		return name;
	}

	/**
	 * Returns the offsets to the start of this
	 * partition's data payload.
	 * @return offsets to the partition's data
	 */
	public abstract long getDataStartOffset();

	/**
	 * Returns the partition's data payload size.
	 * @return the partition's data payload size
	 */
	public abstract int getDataSize();

	/**
	 * Returns true if this partition represents a file.
	 * @return true if this partition represents a file
	 */
	public abstract boolean isFile();

	/**
	 * Returns the offset to the next partition (for non-adjoining partitions).
	 * Returns 0 is the next partition is adjoingin (immediately following the previous).
	 * @return offset to the next partition, or 0
	 */
	public abstract int getOffsetToNextPartitionTable();

	/**
	 * Returns the partition's index.
	 * @return the partition's index
	 */
	public final int getPartitionIndex() {
		return partitionIndex;
	}

	/**
	 * Annotates the program with this partition's data structures.
	 * @param program the program to markup
	 * @param address the address of the partition
	 * @param monitor the task monitor
	 * @param log the message log
	 * @throws Exception if any exception occurs during markup
	 */
	public void markup(Program program, Address address, TaskMonitor monitor, MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);

		DataType partitionDataType = toDataType();

		Data partitionData = program.getListing().createData(address, partitionDataType);

		if (partitionData == null) {
			log.appendMsg("Unable to apply partition data, stopping - " + address);
			return;
		}

		program.getListing()
				.setComment(address, CodeUnit.PLATE_COMMENT,
					getName() + " - " + getPartitionIndex());

		api.createFragment(getName(), address, partitionDataType.getLength());

		Address dataStart = api.toAddr(getDataStartOffset());
		api.createFragment(getName(), dataStart, getDataSize());

		Data offsetData = partitionData.getComponent(2);
		api.createMemoryReference(offsetData, dataStart, RefType.DATA);

		address = address.add(partitionDataType.getLength());
	}
}
