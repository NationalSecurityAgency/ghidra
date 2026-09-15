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
 * Represents a {@code IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION} structure
 */
public class ImageImportControlTransferDynamicRelocation implements StructConverter, PeMarkupable {

	private int pageRelativeOffset;
	private boolean indirectCall;
	private int iatIndex;

	// TODO: IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION has a different bitfield

	private long rva;

	/**
	 * Creates a new {@link ImageImportControlTransferDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 *   {@link ImageDynamicRelocation DVRT entry}
	 * @throws IOException if there was an IO-related error
	 */
	public ImageImportControlTransferDynamicRelocation(BinaryReader reader, long rva)
			throws IOException {
		this.rva = rva;

		int bitfield = reader.readNextInt();
		pageRelativeOffset = bitfield & 0xfff;
		indirectCall = ((bitfield >> 12) & 0x1) != 0;
		iatIndex = (bitfield >> 13) & 0x7ffff;
	}

	/**
	 * {@return the page relative offset}
	 */
	public int getPageRelativeOffset() {
		return pageRelativeOffset;
	}

	/**
	 * {@return whether or not it's an indirect call}
	 */
	public boolean isIndirectCall() {
		return indirectCall;
	}

	/**
	 * {@return the IAT index}
	 */
	public int getIatIndex() {
		return iatIndex;
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
			new StructureDataType("IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION", 0);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(DWORD, 12, "PageRelativeOffset", null);
			struct.addBitField(DWORD, 1, "IndirectCall", null);
			struct.addBitField(DWORD, 19, "IATIndex", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
