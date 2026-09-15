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
 * Represents a {@code IMAGE_BDD_INFO} structure
 */
public class ImageBddInfo implements StructConverter, PeMarkupable {

	private int version;
	private int bddSize;

	private long rva;
	private List<ImageBddDynamicRelocation> bddNodes = new ArrayList<>();

	/**
	 * Creates a new {@link ImageBddInfo}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageBddInfo(BinaryReader reader, long rva) throws IOException {
		this.rva = rva;
		long origIndex = reader.getPointerIndex();

		version = reader.readNextInt();
		bddSize = reader.readNextInt();

		long startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < startIndex + bddSize; i = reader.getPointerIndex()) {
			bddNodes.add(new ImageBddDynamicRelocation(reader,
				rva + (reader.getPointerIndex() - origIndex)));
		}
	}

	/**
	 * {@return the BDD version} 
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * {@return the BDD size}
	 */
	public int getBddSize() {
		return bddSize;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		PeUtils.createData(program, imageBase.add(rva), dt, log);
		for (ImageBddDynamicRelocation node : bddNodes) {
			node.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_BDD_INFO", 0);
		struct.add(DWORD, "Version", "decides the semantics of serialzed BDD");
		struct.add(DWORD, "BDDSize", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

}
