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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ImportAddressTableDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_IAT";

    private List<ThunkData []> thunkDataSetList;

    static ImportAddressTableDataDirectory createImportAddressTableDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        ImportAddressTableDataDirectory importAddressTableDataDirectory = (ImportAddressTableDataDirectory) reader.getFactory().create(ImportAddressTableDataDirectory.class);
        importAddressTableDataDirectory.initImportAddressTableDataDirectory(ntHeader, reader);
        return importAddressTableDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public ImportAddressTableDataDirectory() {}

	private void initImportAddressTableDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
	}

	/**
	 * Returns the thunk data set at the specified index.
	 * @param index the desired thunk data index
	 * @return the thunk data array at the specified index
	 */
	public ThunkData [] getThunkDataSet(int index) {
		return thunkDataSetList.get(index);
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws CodeUnitInsertionException, MemoryAccessException {

		monitor.setMessage(program.getName()+": IAT...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
	}

	@Override
	public boolean parse() throws IOException {
		thunkDataSetList = new ArrayList<ThunkData []>();

		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}

		List<ThunkData> thunkList = new ArrayList<ThunkData>();

		if (size > NTHeader.MAX_SANE_COUNT * 8) {
			Msg.error(this, "Large ImportAddressTable not parsed, size = "+size);
			return false;
		}
		int tmp = size;

    	while (tmp > 0) {
			ThunkData thunk = ThunkData.createThunkData(reader, ptr, ntHeader.getOptionalHeader().is64bit());

			if (thunk.getAddressOfData() == 0) {
				ThunkData [] set = new ThunkData[thunkList.size()];
				thunkList.toArray(set);
				thunkList.clear();
				thunkDataSetList.add(set);
			}
			else {
				thunkList.add(thunk);
			}

			ptr += thunk.getStructSize();
			tmp -= thunk.getStructSize();
    	}
    	return true;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, 0);
        struct.add(new ArrayDataType(BYTE, size, 1), "IAT", null);
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }
}
