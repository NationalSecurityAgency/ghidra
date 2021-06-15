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
import java.util.*;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Points to the delayload information. 
 * See DELAYIMP.H from Visual C++. 
 */
public class DelayImportDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT";

    private DelayImportDescriptor [] descriptors; 

    static DelayImportDataDirectory createDelayImportDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        DelayImportDataDirectory delayImportDataDirectory = (DelayImportDataDirectory) reader.getFactory().create(DelayImportDataDirectory.class);
        delayImportDataDirectory.initDelayImportDataDirectory(ntHeader, reader);
        return delayImportDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DelayImportDataDirectory() {}

	private void initDelayImportDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);

        if (descriptors == null) descriptors = new DelayImportDescriptor[0];
	}

	/**
	 * Returns the array of delay import descriptors defined in this delay import data directory.
	 * @return the array of delay import descriptors defined in this delay import data directory
	 */
    public DelayImportDescriptor [] getDelayImportDescriptors() {
        return descriptors;
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

        List<DelayImportDescriptor> list = new ArrayList<DelayImportDescriptor>();
        while (true) {
            DelayImportDescriptor did = DelayImportDescriptor.createDelayImportDescriptor(ntHeader, reader, ptr);

            if (!did.isValid() || did.getPointerToDLLName() == 0) break;

            list.add(did);

            ptr += did.sizeof();
        }

        descriptors = new DelayImportDescriptor[list.size()];
        list.toArray(descriptors);
        return true;
    }

    @Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {

    	monitor.setMessage(program.getName()+": delay import(s)...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		for (DelayImportDescriptor descriptor : descriptors) {
			if (monitor.isCancelled()) {
				return;
			}
			//apply descriptor structure
			PeUtils.createData(program, addr, descriptor.toDataType(), log);
			createSymbol(program, addr,
				SymbolUtilities.getAddressAppendedName(DelayImportDescriptor.NAME, addr));

			Data data = program.getListing().getDataAt(addr);
			if (data == null || !data.isDefined()) continue;
			if (data.getNumComponents() < 7) {
				Msg.info(this, "Unexpected data at "+addr);
				continue;
			}

			//create string for descriptor dll name
			Address tmpAddr = addr(space, isBinary, descriptor, descriptor.getPointerToDLLName());
			createTerminatedString(program, tmpAddr, true, log);

			tmpAddr = addr(space, isBinary, descriptor, descriptor.getAddressOfModuleHandle());
			createSymbol(program, tmpAddr, SymbolUtilities.getAddressAppendedName(
				DelayImportDescriptor.NAME + "_Module_Handle", tmpAddr));

			tmpAddr = addr(space, isBinary, descriptor, descriptor.getAddressOfIAT());
			createSymbol(program, tmpAddr, SymbolUtilities.getAddressAppendedName(
				DelayImportDescriptor.NAME + "_IAT", tmpAddr));
			markupThunk(program, isBinary, space, descriptor, descriptor.getAddressOfIAT(),
				descriptor.getThunksIAT(), true, monitor, log);

			tmpAddr = addr(space, isBinary, descriptor, descriptor.getAddressOfINT());
			createSymbol(program, tmpAddr, SymbolUtilities.getAddressAppendedName(
				DelayImportDescriptor.NAME + "_INT", tmpAddr));
			markupThunk(program, isBinary, space, descriptor, descriptor.getAddressOfINT(),
				descriptor.getThunksINT(), false, monitor, log);

			// This table is optional
			if (descriptor.getAddressOfBoundIAT() != 0) {
				tmpAddr = addr(space, isBinary, descriptor, descriptor.getAddressOfBoundIAT());
				createSymbol(program, tmpAddr, SymbolUtilities.getAddressAppendedName(
					DelayImportDescriptor.NAME + "_Bound_IAT", tmpAddr));
				markupThunk(program, isBinary, space, descriptor, descriptor.getAddressOfBoundIAT(),
					descriptor.getThunksBoundIAT(), false, monitor, log);
			}

			// This table is optional
			if (descriptor.getAddressOfOriginalIAT() != 0) {
				tmpAddr = addr(space, isBinary, descriptor, descriptor.getAddressOfOriginalIAT());
				createSymbol(program, tmpAddr, SymbolUtilities.getAddressAppendedName(
					DelayImportDescriptor.NAME + "_Unload_IAT", tmpAddr));
				markupThunk(program, isBinary, space, descriptor,
					descriptor.getAddressOfOriginalIAT(), descriptor.getThunksUnloadIAT(), false,
					monitor, log);
			}


			markupImportByName(program, isBinary, space, descriptor, monitor, log);

			addr = addr.add(descriptor.sizeof());
		}
    }

    private void createSymbol(Program program, Address addr, String name) {
		try {
			program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
		}
		catch (Exception e) {}
	}

    private Address addr(AddressSpace space, boolean isBinary, 
			DelayImportDescriptor descriptor, long addr) {

    	if (!isBinary) {
    		if (descriptor.isUsingRVA()) {
    			return space.getAddress(addr + ntHeader.getOptionalHeader().getImageBase());
    		}
    		return space.getAddress(addr);
    	}
		if (!descriptor.isUsingRVA()) {
			addr -= ntHeader.getOptionalHeader().getImageBase();
		}
    	long va = va(addr, isBinary);
		return space.getAddress(va);
	}

	private void markupImportByName(Program program, 
									boolean isBinary, 
									AddressSpace space, 
									DelayImportDescriptor descriptor, 
									TaskMonitor monitor,
									MessageLog log)
			throws DataTypeConflictException, DuplicateNameException {

		Map<ThunkData, ImportByName> map = descriptor.getImportByNameMap();
		Iterator<ThunkData> thunks = map.keySet().iterator();
		while (thunks.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}
			ThunkData thunk = thunks.next();
			long thunkPtr = va(thunk.getAddressOfData(), isBinary);
			if (!descriptor.isUsingRVA()) {
				thunkPtr -= ntHeader.getOptionalHeader().getImageBase();
			}
			Address thunkAddress = space.getAddress(thunkPtr);
			ImportByName ibn = map.get(thunk);
			PeUtils.createData(program, thunkAddress, ibn.toDataType(), log);
		}
	}

	private void markupThunk(Program program, 
						boolean isBinary, 
						AddressSpace space, 
						DelayImportDescriptor descriptor,
						long ptr,
						List<ThunkData> thunks,
						boolean isIAT,
						TaskMonitor monitor,
						MessageLog log) {
		
		boolean is64bit = ntHeader.getOptionalHeader().is64bit();
		long thunkPtr = va(ptr, isBinary);
		if (!descriptor.isUsingRVA()) {
			thunkPtr -= ntHeader.getOptionalHeader().getImageBase();
		}

		for (ThunkData thunk : thunks) {
			if (monitor.isCancelled()) {
				return;
			}
			DataType dt;
			if (thunk.isOrdinal() || thunk.getAddressOfData() == 0) {
				dt = is64bit ? QWORD : DWORD;
			}
			else if (isIAT) {
				dt = is64bit ? Pointer64DataType.dataType : Pointer32DataType.dataType;
			}
			else {
				dt = is64bit ? IBO64 : IBO32;
			}

			Address thunkAddress = space.getAddress(thunkPtr);
			PeUtils.createData(program, thunkAddress, dt, log);
			setEolComment(program, thunkAddress, thunk.getStructName());
			thunkPtr += thunk.getStructSize();
		}
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(NAME, 0);
        for (DelayImportDescriptor descriptor : descriptors) {
			struct.add(descriptor.toDataType(), DelayImportDescriptor.NAME, null);
		}
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }
}
