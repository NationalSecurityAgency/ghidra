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
 * Represents a {@code IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION} structure
 */
public class ImageFunctionOverrideDynamicRelocation implements StructConverter, PeMarkupable {

	private int originalRva;
	private int bddOffset;
	private int rvaSize;
	private int baseRelocSize;

	private long rva;
	private int[] rvas;
	private List<BaseRelocation> baseRelocs = new ArrayList<>();

	/**
	 * Creates a new {@link ImageFunctionOverrideDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageFunctionOverrideDynamicRelocation(BinaryReader reader, long rva)
			throws IOException {
		this.rva = rva;
		
		originalRva = reader.readNextInt();
		bddOffset = reader.readNextInt();
		rvaSize = reader.readNextInt();
		baseRelocSize = reader.readNextInt();

		rvas = reader.readNextIntArray(rvaSize / 4);

		long startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < startIndex + baseRelocSize; i = reader.getPointerIndex()) {
			baseRelocs.add(new BaseRelocation(reader));
		}
	}

	/**
	 * {@return the relative virtual address of the original function}
	 */
	public int getOriginalRva() {
		return originalRva;
	}

	/**
	 * {@return the offset into the BDD region}
	 */
	public int getBddOffset() {
		return bddOffset;
	}

	/**
	 * {@return the size in bytes taken by relative virtual addresses}
	 */
	public int getRvaSize() {
		return rvaSize;
	}

	/**
	 * {@return the size in bytes taken by BaseRelocs}
	 */
	public int getBaseRelocSize() {
		return baseRelocSize;
	}

	/**
	 * {@return the {@link List} of {@link BaseRelocation}s}
	 */
	public List<BaseRelocation> getBaseRelocs() {
		return baseRelocs;
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
		for (int i = 0; i < rvas.length; i++) {
			PeUtils.createData(program, addr, DWORD, log);
			addr = addr.add(DWORD.getLength());
		}
		for (BaseRelocation baseReloc : baseRelocs) {
			baseReloc.markup(program, addr, isBinary, monitor, log, ntHeader);
			addr = addr.add(baseReloc.getSizeOfBlock());
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct =
			new StructureDataType("IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION", 0);
		struct.add(DWORD, "OriginalRva", "RVA of original function");
		struct.add(DWORD, "BDDOffset", "Offset into the BDD region");
		struct.add(DWORD, "RvaSize",
			"Size in bytes taken by RVAs. Must be multiple of sizeof(DWORD).");
		struct.add(DWORD, "BaseRelocSize", "Size in bytes taken by BaseRelocs");
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
