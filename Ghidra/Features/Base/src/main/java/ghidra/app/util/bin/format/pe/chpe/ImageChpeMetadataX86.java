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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_CHPE_METADATA_X86} structure
 */
@SuppressWarnings("unused")
public class ImageChpeMetadataX86 implements StructConverter, PeMarkupable {

	private int version;
	private int chpeCodeAddressRangeOffset;
	private int chpeCodeAddressRangeCount;
	private int wowA64ExceptionHandlerFunctionPointer;
	private int wowA64DispatchCallFunctionPointer;
	private int wowA64DispatchIndirectCallFunctionPointer;
	private int wowA64DispatchIndirectCallCfgFunctionPointer;
	private int wowA64DispatchRetFunctionPointer;
	private int wowA64DispatchRetLeafFunctionPointer;
	private int wowA64DispatchJumpFunctionPointer;
	private int compilerIatPointer;
	private int wowA64RdtscFunctionPointer;
	private int unknown1;
	private int unknown2;
	private int unknown3;
	private int unknown4;

	private long va;
	private List<ImageChpeRangeEntry> codeMapEntries = new ArrayList<>();

	/**
	 * Creates a new {@link ImageChpeMetadataX86}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param nt The {@link NTHeader}
	 * @param va The virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageChpeMetadataX86(BinaryReader reader, NTHeader nt, long va) throws IOException {
		this.va = va;

		version = reader.readNextInt();
		chpeCodeAddressRangeOffset = reader.readNextInt();
		chpeCodeAddressRangeCount = reader.readNextInt();
		wowA64ExceptionHandlerFunctionPointer = reader.readNextInt();
		wowA64DispatchCallFunctionPointer = reader.readNextInt();
		wowA64DispatchIndirectCallFunctionPointer = reader.readNextInt();
		wowA64DispatchIndirectCallCfgFunctionPointer = reader.readNextInt();
		wowA64DispatchRetFunctionPointer = reader.readNextInt();
		wowA64DispatchRetLeafFunctionPointer = reader.readNextInt();
		wowA64DispatchJumpFunctionPointer = reader.readNextInt();
		if (version >= 2) {
			compilerIatPointer = reader.readNextInt();
		}
		if (version >= 3) {
			wowA64RdtscFunctionPointer = reader.readNextInt();
		}
		if (version >= 4) {
			unknown1 = reader.readNextInt();
			unknown2 = reader.readNextInt();
			unknown3 = reader.readNextInt();
			unknown4 = reader.readNextInt();
		}

		BinaryReader r = reader.clone(nt.rvaToPointer(chpeCodeAddressRangeOffset));
		long startIndex = r.getPointerIndex();
		for (int i = 0; i < chpeCodeAddressRangeCount; i++) {
			codeMapEntries.add(new ImageChpeRangeEntry(r,
				chpeCodeAddressRangeOffset + (r.getPointerIndex() - startIndex)));
		}
	}

	/**
	 * {@return the metadata version}
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * {@return the {@link List} of {@link ImageChpeRangeEntry code map entries}}
	 */
	public List<ImageChpeRangeEntry> getCodeMapEntries() {
		return codeMapEntries;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		PeUtils.createData(program, space.getAddress(va), toDataType(), log);
		for (ImageChpeRangeEntry entry : codeMapEntries) {
			entry.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_CHPE_METADATA_X86", 0);
		struct.add(DWORD, "Version", null);
		struct.add(IBO32, "CHPECodeAddressRangeOffset", null);
		struct.add(DWORD, "CHPECodeAddressRangeCount", null);
		struct.add(IBO32, "WowA64ExceptionHandlerFunctionPointer", null);
		struct.add(IBO32, "WowA64DispatchCallFunctionPointer", null);
		struct.add(IBO32, "WowA64DispatchIndirectCallFunctionPointer", null);
		struct.add(IBO32, "WowA64DispatchIndirectCallCfgFunctionPointer", null);
		struct.add(IBO32, "WowA64DispatchRetFunctionPointer", null);
		struct.add(IBO32, "WowA64DispatchRetLeafFunctionPointer", null);
		struct.add(IBO32, "WowA64DispatchJumpFunctionPointer", null);
		if (version >= 2) {
			struct.add(IBO32, "CompilerIATPointer", null);
		}
		if (version >= 3) {
			struct.add(IBO32, "WowA64RdtscFunctionPointer", null);
		}
		if (version >= 4) {
			struct.add(IBO32, "Unknown1", null);
			struct.add(IBO32, "Unknown2", null);
			struct.add(IBO32, "Unknown3", null);
			struct.add(IBO32, "Unknown4", null);
		}
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
