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
package ghidra.app.util.bin.format.pe.chpe;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT} structure
 */
public class ImageArm64ecCodeRangeEntryPoint implements StructConverter, PeMarkupable {

	private int startRva;
	private int endRva;
	private int entryPoint;

	private long rva;

	/**
	 * Creates a new {@link ImageArm64ecCodeRangeEntryPoint}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageArm64ecCodeRangeEntryPoint(BinaryReader reader, long rva) throws IOException {
		this.rva = rva;

		startRva = reader.readNextInt();
		endRva = reader.readNextInt();
		entryPoint = reader.readNextInt();
	}

	/**
	 * {@return the start RVA}
	 */
	public int getStartRva() {
		return startRva;
	}

	/**
	 * {@return the end RVA}
	 */
	public int getEndRva() {
		return endRva;
	}

	/**
	 * {@return the entry point RVA}
	 */
	public int getEntryPoint() {
		return entryPoint;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		PeUtils.createData(program, imageBase.add(rva), dt, log);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT", 0);
		struct.add(IBO32, "StartRva", null);
		struct.add(IBO32, "EndRva", null);
		struct.add(IBO32, "EntryPoint", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
