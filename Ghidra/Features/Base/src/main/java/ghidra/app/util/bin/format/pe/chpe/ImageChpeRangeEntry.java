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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_CHPE_RANGE_ENTRY} structure
 */
public class ImageChpeRangeEntry implements StructConverter, PeMarkupable {

	private static final int TYPE_MASK = 0x3;
	private static final int OFFSET_MASK = ~TYPE_MASK;

	private ChpeRangeType type;
	private int startOffset;
	private long length;

	private long rva;

	/**
	 * Creates a new {@link ImageChpeRangeEntry}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageChpeRangeEntry(BinaryReader reader, long rva) throws IOException {
		this.rva = rva;

		int value = reader.readNextInt();
		type = ChpeRangeType.type(value & TYPE_MASK);
		startOffset = value & OFFSET_MASK;
		length = reader.readNextUnsignedInt();
	}

	/**
	 * {@return the {@link ChpeRangeType type} of range}
	 */
	public ChpeRangeType getRangeType() {
		return type;
	}

	/**
	 * {@return the start offset of the range}
	 */
	public int getStartOffset() {
		return startOffset;
	}

	/**
	 * {@return the length of the range}
	 */
	public long getLength() {
		return length;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		Address addr = imageBase.add(rva);
		PeUtils.createData(program, addr, dt, log);
		program.getListing().setComment(addr, CommentType.PLATE, type.name());
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		TypeDef offsetPtr =
			new PointerTypedefBuilder(Pointer32DataType.dataType, null)
					.type(PointerType.IMAGE_BASE_RELATIVE)
					.bitMask(OFFSET_MASK)
					.build();

		StructureDataType struct = new StructureDataType("IMAGE_CHPE_RANGE_ENTRY", 0);
		struct.add(offsetPtr, "StartOffset", null);
		struct.add(DWORD, "Length", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
