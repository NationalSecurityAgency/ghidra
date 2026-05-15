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
 * Represents a {@code IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION} structure
 */
public class ImageIndirControlTransferDynamicRelocation implements StructConverter, PeMarkupable {

	private int pageRelativeOffset;
	private boolean indirectCall;
	private boolean rexWPrefix;
	private boolean cfgCheck;
	private int reserved;

	private long rva;

	/**
	 * Creates a new {@link ImageIndirControlTransferDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageIndirControlTransferDynamicRelocation(BinaryReader reader, long rva)
			throws IOException {
		this.rva = rva;

		int bitfield = reader.readNextUnsignedShort();
		pageRelativeOffset = bitfield & 0xfff;
		indirectCall = ((bitfield >> 12) & 0x1) != 0;
		rexWPrefix = ((bitfield >> 13) & 0x1) != 0;
		cfgCheck = ((bitfield >> 14) & 0x1) != 0;
		reserved = (bitfield >> 15) & 0x1;
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
	 * {@return whether or not there is a rexw prefix}
	 */
	public boolean isRexWPrefix() {
		return rexWPrefix;
	}

	/**
	 * {@return whether or not it's a CFG check}
	 */
	public boolean isCfgCheck() {
		return cfgCheck;
	}

	/**
	 * {@return the reserved bit}
	 */
	public int getReserved() {
		return reserved;
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
			new StructureDataType("IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION", 0);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(WORD, 12, "PageRelativeOffset", null);
			struct.addBitField(WORD, 1, "IndirectCall", null);
			struct.addBitField(WORD, 1, "RexWPrefix", null);
			struct.addBitField(WORD, 1, "CfgCheck", null);
			struct.addBitField(WORD, 1, "Reserved", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

}
