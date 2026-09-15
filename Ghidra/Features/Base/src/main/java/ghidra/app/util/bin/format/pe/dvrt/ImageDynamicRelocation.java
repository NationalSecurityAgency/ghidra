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
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_DYNAMIC_RELOCATION} structure
 */
public class ImageDynamicRelocation implements StructConverter, PeMarkupable {

	private DvrtType symbol;
	private int baseRelocSize;

	private long rva;
	private boolean is64bit;
	private List<AbstractImageDynamicRelocationHeader> headers = new ArrayList<>();

	/**
	 * Creates a new {@link ImageDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @param is64bit True if 64-bit; otherwise, false
	 * @throws IOException if there was an IO-related error
	 */
	public ImageDynamicRelocation(BinaryReader reader, long rva, boolean is64bit)
			throws IOException {
		this.rva = rva;
		this.is64bit = is64bit;
		long origIndex = reader.getPointerIndex();
		
		symbol = is64bit ? reader.readNext(DvrtType::type8)
				: reader.readNext(DvrtType::type4).changeSize(4);
		baseRelocSize = reader.readNextInt();

		long startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < startIndex + baseRelocSize; i = reader.getPointerIndex()) {
			long newRva = rva + (i - origIndex);
			headers.add(switch (symbol) {
				case IMAGE_DYNAMIC_RELOCATION_IMPORT_CONTROL_TRANSFER -> new ImageImportControlTransfer(
					reader, newRva);
				case IMAGE_DYNAMIC_RELOCATION_INDIR_CONTROL_TRANSFER -> new ImageIndirControlTransfer(
					reader, newRva);
				case IMAGE_DYNAMIC_RELOCATION_SWITCHABLE_BRANCH -> new ImageSwitchtableBranch(
					reader, newRva);
				case IMAGE_DYNAMIC_RELOCATION_ARM64X -> new ImageArm64X(reader, newRva);
				case IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE -> new ImageFunctionOverrideHeader(
					reader, newRva, baseRelocSize);
				case IMAGE_DYNAMIC_RELOCATION_UNKNOWN -> new ImageUnsupportedRelocationHeader(
					reader, newRva, baseRelocSize);
				default -> new ImageUnsupportedRelocationHeader(reader, newRva, baseRelocSize);
			});
		}
	}

	/**
	 * {@return the relocation "symbol", which is really a {@link DvrtType type}}
	 */
	public DvrtType getSymbol() {
		return symbol;
	}

	/**
	 * {@return the size in bytes of the relocation}
	 */
	public int getBaseRelocSize() {
		return baseRelocSize;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Listing listing = program.getListing();
		Address imageBase = program.getImageBase();
		Address start = imageBase.add(rva);
		PeUtils.createData(program, start, toDataType(), log);
		for (AbstractImageDynamicRelocationHeader header : headers) {
			header.markup(program, isBinary, monitor, log, ntHeader);
		}
		listing.setComment(start, CommentType.PLATE, symbol.name());
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name ="IMAGE_DYNAMIC_RELOCATION";
		DataType symbolType = symbol.toDataType();
		if (symbol == DvrtType.IMAGE_DYNAMIC_RELOCATION_UNKNOWN) {
			name += "_UNKNOWN";
			symbolType = is64bit ? QWORD : DWORD;
		}
		StructureDataType struct = new StructureDataType(name, 0);
		struct.add(symbolType, "Symbol", null);
		struct.add(DWORD, "BaseRelocSize", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

}
