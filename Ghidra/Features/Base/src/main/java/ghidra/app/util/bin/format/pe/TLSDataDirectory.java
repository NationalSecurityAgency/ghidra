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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Points to the Thread Local Storage initialization section.
 */
public class TLSDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_TLS";

    private TLSDirectory tls;

    static TLSDataDirectory createTLSDataDirectory(NTHeader ntHeader,
            FactoryBundledWithBinaryReader reader) throws IOException {
        TLSDataDirectory tlsDataDirectory = (TLSDataDirectory) reader.getFactory().create(TLSDataDirectory.class);
        tlsDataDirectory.initTLSDataDirectory(ntHeader, reader);
        return tlsDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public TLSDataDirectory() {}

	private void initTLSDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
	}

	/**
	 * Returns the thread local storage directory.
	 * @return the thread local storage directory
	 */
	public TLSDirectory getTLSDirectory() {
		return tls;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {

		monitor.setMessage(program.getName()+": TLS...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
		PeUtils.createData(program, addr, tls.toDataType(), log);

		// Markup TLS callback functions
		if (tls.getAddressOfCallBacks() != 0) {
			AddressSpace space = program.getImageBase().getAddressSpace();
			DataType pointerDataType = PointerDataType.dataType.clone(program.getDataTypeManager());
			try {
				for (int i = 0; i < 20; i++) { // cap # of TLS callbacks as a precaution (1 is the norm)
					Address nextCallbackPtrAddr = space.getAddress(
						tls.getAddressOfCallBacks() + i * pointerDataType.getLength());
					Address nextCallbackAddr = PointerDataType.getAddressValue(
						new DumbMemBufferImpl(program.getMemory(), nextCallbackPtrAddr),
						pointerDataType.getLength(), space);
					if (nextCallbackAddr.getOffset() == 0) {
						break;
					}
					PeUtils.createData(program, nextCallbackPtrAddr, pointerDataType, log);
					program.getSymbolTable().createLabel(nextCallbackAddr, "tls_callback_" + i,
						SourceType.IMPORTED);
					program.getSymbolTable().addExternalEntryPoint(nextCallbackAddr);
				}
			}
			catch (InvalidInputException e) {
				log.appendMsg("TLS", "Failed to markup TLS callback functions: " + e.getMessage());
			}
		}
	}

	@Override
	public boolean parse() throws IOException {
		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}

        tls = TLSDirectory.createTLSDirectory(reader, ptr, ntHeader.getOptionalHeader().is64bit());
        return true;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException {
		return tls.toDataType();
    }
}
