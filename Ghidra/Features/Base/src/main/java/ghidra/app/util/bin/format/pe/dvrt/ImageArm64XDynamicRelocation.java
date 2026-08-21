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
 * Represents a {@code IMAGE_ARM64X_DYNAMIC_RELOCATION} structure
 */
public class ImageArm64XDynamicRelocation implements StructConverter, PeMarkupable {

	private int pageRelativeOffset;
	private int type;
	private int meta;
	private byte[] data;

	private long rva;

	/**
	 * Creates a new {@link ImageArm64XDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageArm64XDynamicRelocation(BinaryReader reader, long rva) throws IOException {
		this.rva = rva;

		int bitfield = reader.readNextUnsignedShort();
		if (bitfield == 0) {
			data = new byte[0];
			return;
		}

		pageRelativeOffset = bitfield & 0xfff;
		type = (bitfield >> 12) & 0x3;
		meta = (bitfield >> 14) & 0x3;

		int size = switch (type) {
			case 0 -> 0; // zero fill
			case 1 -> 1 << meta; // assign value
			case 2 -> 2; // add (or sub) delta
			default -> 2;
		};
		data = reader.readNextByteArray(size);
	}

	/**
	 * {@return the page relative offset}
	 */
	public int getPageRelativeOffset() {
		return pageRelativeOffset;
	}

	/**
	 * {@return the type}
	 */
	public int getType() {
		return type;
	}

	/**
	 * {@return the data}
	 */
	public byte[] getData() {
		return data;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		Address addr = imageBase.add(rva);
		PeUtils.createData(program, addr, dt, log);
		addr = addr.add(dt.getLength());
		DataType dataDt = switch (data.length) {
			case 1 -> BYTE;
			case 2 -> WORD;
			case 4 -> DWORD;
			case 8 -> QWORD;
			default -> null;
		};
		if (dataDt != null) {
			PeUtils.createData(program, addr, dataDt, log);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct =
			new StructureDataType("IMAGE_ARM64X_DYNAMIC_RELOCATION", 0);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(WORD, 12, "PageRelativeOffset", null);
			struct.addBitField(WORD, 2, "Type", null);
			struct.addBitField(WORD, 2, "Meta", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}

