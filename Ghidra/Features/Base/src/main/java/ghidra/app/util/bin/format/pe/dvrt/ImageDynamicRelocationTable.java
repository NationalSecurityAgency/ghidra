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
import java.util.ArrayList;
import java.util.List;

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
 * Represents a {@code IMAGE_DYNAMIC_RELOCATION_TABLE} structure
 */
public class ImageDynamicRelocationTable implements StructConverter, PeMarkupable {

	private int version;
	private int size;

	private long rva;
	private List<ImageDynamicRelocation> relocations = new ArrayList<>();

	/**
	 * Creates a new {@link ImageDynamicRelocationTable}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @param is64bit True if 64-bit; otherwise, false
	 * @throws IOException if there was an IO-related error
	 */
	public ImageDynamicRelocationTable(BinaryReader reader, long rva, boolean is64bit)
			throws IOException {
		this.rva = rva;
		long origIndex = reader.getPointerIndex();

		version = reader.readNextInt();
		size = reader.readNextInt();

		if (version != 1) {
			// TODO: support version 2
			return;
		}

		long startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < startIndex + size; i = reader.getPointerIndex()) {
			relocations.add(new ImageDynamicRelocation(reader, rva + (i - origIndex), is64bit));
		}
	}

	/**
	 * {@return the dynamic value relocation table version}
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * {@return the size in bytes of the dynamic value relocation table}
	 */
	public int getSize() {
		return size;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		PeUtils.createData(program, imageBase.add(rva), toDataType(), log);
		for (ImageDynamicRelocation reloc : relocations) {
			reloc.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_DYNAMIC_RELOCATION_TABLE", 0);
		struct.add(DWORD, "Version", null);
		struct.add(DWORD, "Size", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
