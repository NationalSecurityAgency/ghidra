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
package ghidra.app.util.bin.format.pe.dvrt;

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
 * Represents a {@code IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION} structure
 */
public class ImageSwitchtableBranchDynamicRelocation implements StructConverter, PeMarkupable {

	private int pageRelativeOffset;
	private int registerNumber;

	private long rva;

	/**
	 * Creates a new {@link ImageSwitchtableBranchDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 *   {@link ImageDynamicRelocation DVRT entry}
	 * @throws IOException if there was an IO-related error
	 */
	public ImageSwitchtableBranchDynamicRelocation(BinaryReader reader, long rva)
			throws IOException {
		this.rva = rva;

		int bitfield = reader.readNextUnsignedShort();
		pageRelativeOffset = bitfield & 0xfff;
		registerNumber = (bitfield >> 12) & 0xf;
	}

	/**
	 * {@return the page relative offset}
	 */
	public int getPageRelativeOffset() {
		return pageRelativeOffset;
	}

	/**
	 * {@return the register number}
	 */
	public int getRegisterNumber() {
		return registerNumber;
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
		StructureDataType struct =
			new StructureDataType("IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION", 0);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(WORD, 12, "PageRelativeOffset", null);
			struct.addBitField(WORD, 4, "RegisterNumber", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
