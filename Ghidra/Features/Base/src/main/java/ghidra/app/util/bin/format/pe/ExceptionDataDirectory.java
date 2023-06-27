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

import static ghidra.app.util.bin.format.pe.FileHeader.*;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ExceptionDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_EXCEPTION";

	private ImageRuntimeFunctionEntries functionEntries;

	ExceptionDataDirectory(NTHeader ntHeader, BinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
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

		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(ptr);

		try {
			functionEntries =
				switch (ntHeader.getFileHeader().getMachine() & IMAGE_FILE_MACHINE_MASK) {
					case IMAGE_FILE_MACHINE_I386:
					case IMAGE_FILE_MACHINE_IA64:
					case IMAGE_FILE_MACHINE_AMD64:
						yield new ImageRuntimeFunctionEntries_X86(reader, size, ntHeader);
					case IMAGE_FILE_MACHINE_ARM:
					case IMAGE_FILE_MACHINE_ARM64:
					case IMAGE_FILE_MACHINE_ARMNT:
						yield new ImageRuntimeFunctionEntries_ARM(reader, size, ntHeader);
					default:
						Msg.error(this,
							String.format("Exception Data unsupported architecture: 0x%02x",
								ntHeader.getFileHeader().getMachine()));
						yield null;
				};
			return true;
		}
		catch (IOException e) {
			Msg.error(this, "Failed to parse " + ExceptionDataDirectory.class.getSimpleName(), e);
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}

		return false;
    }

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {

		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
		if (functionEntries != null) {
			functionEntries.markup(program, addr);
		}
	}

    @Override
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, size);
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }
}
