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
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Contains a list of {@link ImageArm64XDynamicRelocation}s
 */
public class ImageArm64X extends AbstractImageDynamicRelocationHeader {

	private int virtualAddress;
	private int sizeOfBlock;
	private List<ImageArm64XDynamicRelocation> relocs = new ArrayList<>();

	/**
	 * Creates a new {@link ImageIndirControlTransfer}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageArm64X(BinaryReader reader, long rva) throws IOException {
		super(rva);
		long origIndex = reader.getPointerIndex();

		virtualAddress = reader.readNextInt();
		sizeOfBlock = reader.readNextInt();

		long startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < origIndex + sizeOfBlock; i = reader.getPointerIndex()) {
			relocs.add(new ImageArm64XDynamicRelocation(reader, rva + (i - origIndex)));
		}
	}

	/**
	 * {@return the virtual address}
	 */
	public int getVirualAddress() {
		return virtualAddress;
	}

	/**
	 * {@return the size of the block}
	 */
	public int getSizeOfBlock() {
		return sizeOfBlock;
	}

	/**
	 * {@return the {@link List} of {@link ImageArm64XDynamicRelocation}s}
	 */
	public List<ImageArm64XDynamicRelocation> getRelocs() {
		return relocs;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
//		ReferenceManager refMgr = program.getReferenceManager();
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		Address addr = imageBase.add(rva);
		PeUtils.createData(program, addr, dt, log);
		addr = addr.add(dt.getLength());
		for (ImageArm64XDynamicRelocation reloc : relocs) {
			reloc.markup(program, isBinary, monitor, log, ntHeader);
//			int pageRelativeOffset = reloc.getPageRelativeOffset();
//			if (pageRelativeOffset != 0) {
//				refMgr.addMemoryReference(addr, imageBase.add(virtualAddress + pageRelativeOffset),
//					RefType.DATA, SourceType.IMPORTED, 0);
//			}
			addr = addr.add(reloc.toDataType().getLength() + reloc.getData().length);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_ARM64X", 0);
		struct.add(DWORD, "VirtualAddress", null);
		struct.add(DWORD, "SizeOfBlock", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
