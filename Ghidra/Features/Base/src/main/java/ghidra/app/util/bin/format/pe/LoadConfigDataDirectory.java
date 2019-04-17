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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.ImageBaseOffset32DataType;
import ghidra.program.model.data.ImageBaseOffset64DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class LoadConfigDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG";

    private LoadConfigDirectory lcd;

    static LoadConfigDataDirectory createLoadConfigDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        LoadConfigDataDirectory loadConfigDataDirectory = (LoadConfigDataDirectory) reader.getFactory().create(LoadConfigDataDirectory.class);
        loadConfigDataDirectory.initLoadConfigDataDirectory(ntHeader, reader);
        return loadConfigDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public LoadConfigDataDirectory() {}

	private void initLoadConfigDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
	}

	/**
	 * Returns the load config directory object defined in this data directory.
	 * @return the load config directory object
	 */
	public LoadConfigDirectory getLoadConfigDirectory() {
		return lcd;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {

		monitor.setMessage(program.getName()+": load config directory...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
		
		PeUtils.createData(program, addr, lcd.toDataType(), log);

		markupSeHandler(program, isBinary, monitor, log, ntHeader);
		ControlFlowGuard.markup(lcd, program, log, ntHeader);
	}

	private void markupSeHandler(Program program, boolean isBinary, TaskMonitor monitor,
			MessageLog log, NTHeader ntHeader) {
		long exceptionCount = lcd.getSeHandlerCount();
		long exceptionTable = lcd.getSeHandlerTable() - ntHeader.getOptionalHeader().getImageBase();
		if (exceptionCount > NTHeader.MAX_SANE_COUNT) {
			// a heuristic but...
			return;
		}

		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
			va(exceptionTable, isBinary));
		setPlateComment(program, addr,
			"SEHandlerTable (0x" + Long.toHexString(exceptionCount) + " entries)");

		for (int i = 0; i < (int) exceptionCount; ++i) {
			if (monitor.isCancelled()) {
				return;
			}
			DataType dt = ntHeader.getOptionalHeader().is64bit() ? new ImageBaseOffset64DataType() : new ImageBaseOffset32DataType();

			PeUtils.createData(program, addr, dt, log);

			addr = addr.add(dt.getLength());
		}
	}

	@Override
	public boolean parse() throws IOException {
		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}

        lcd = LoadConfigDirectory.createLoadConfigDirectory(reader, ptr, ntHeader.getOptionalHeader());
        return true;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException {
    	return lcd.toDataType();
    }
}


