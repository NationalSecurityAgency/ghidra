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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * This value has been renamed to IMAGE_DIRECTORY_ENTRY_COMHEADER.
 */
public class COMDescriptorDataDirectory extends DataDirectory {
	private final static String NAME = "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR";

	private ImageCor20Header header;

	static COMDescriptorDataDirectory createCOMDescriptorDataDirectory(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader) throws IOException {
		COMDescriptorDataDirectory comDescriptorDataDirectory =
			(COMDescriptorDataDirectory) reader.getFactory().create(
				COMDescriptorDataDirectory.class);
		comDescriptorDataDirectory.initCOMDescriptorDataDirectory(ntHeader, reader);
		return comDescriptorDataDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public COMDescriptorDataDirectory() {
	}

	private void initCOMDescriptorDataDirectory(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader) throws IOException {
		this.ntHeader = ntHeader;
		processDataDirectory(ntHeader, reader);
	}

	public ImageCor20Header getHeader() {
		return header;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public boolean parse() throws IOException {
		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}

		header = ImageCor20Header.createImageCor20Header(reader, ptr, ntHeader);

		boolean ret = false;
		if (ntHeader.shouldParseCliHeaders()) {
			ret = header.parse();
		}
		return ret;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {

		monitor.setMessage("[" + program.getName() + "]: com descriptor(s)...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
		DataType dt = header.toDataType();
		PeUtils.createData(program, addr, dt, log);

		if (hasParsed) {
			header.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(new ArrayDataType(BYTE, size, 1), "COM", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
