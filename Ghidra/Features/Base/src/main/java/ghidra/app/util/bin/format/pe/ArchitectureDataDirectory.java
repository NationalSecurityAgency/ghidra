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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ArchitectureDataDirectory extends DataDirectory implements StructConverter {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE";

    private String copyright;

	ArchitectureDataDirectory(NTHeader ntHeader, BinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
    }

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader nt) throws DuplicateNameException, CodeUnitInsertionException {
		monitor.setMessage(program.getName()+": architecture...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, nt, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
		PeUtils.createData(program, addr, toDataType(), log);
	}

	@Override
	public boolean parse() throws IOException {
		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}
        if (getSize() > 1000) {
        	Msg.info(this, "Requesting ASCII string of size "+getSize());
        	return false;
        }
		copyright = reader.readAsciiString(ptr, getSize()).trim();
        return true;
    }

	/**
	 * Returns the copyright string defined in this directory.
	 * @return the copyright string defined in this directory
	 */
    public String getCopyright() {
        return copyright;
    }

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		if (size > 0) {
			struct.add(new StringDataType(), size, "Copyright", null);
		}
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
