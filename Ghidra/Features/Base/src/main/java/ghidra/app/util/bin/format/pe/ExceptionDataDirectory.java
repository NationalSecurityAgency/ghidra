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
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ExceptionDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_EXCEPTION";

	static ExceptionDataDirectory createExceptionDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
	    ExceptionDataDirectory exceptionDataDirectory = (ExceptionDataDirectory) reader.getFactory().create(ExceptionDataDirectory.class);
	    exceptionDataDirectory.initExceptionDataDirectory(ntHeader, reader);
	    return exceptionDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public ExceptionDataDirectory() {}

    private void initExceptionDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public boolean parse() {
		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}
		return true;
    }

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {
		monitor.setMessage(program.getName()+": exceptions...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, size);
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }
}
