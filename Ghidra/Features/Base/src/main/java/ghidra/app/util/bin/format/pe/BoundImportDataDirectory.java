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
import java.io.RandomAccessFile;
import java.util.*;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Points to an array of IMAGE_BOUND_IMPORT_DESCRIPTORs.
 */
public class BoundImportDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT";

    private BoundImportDescriptor [] descriptors;
    private LinkedHashMap<String,Short> nameHash;

    static BoundImportDataDirectory createBoundImportDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        BoundImportDataDirectory boundImportDataDirectory = (BoundImportDataDirectory) reader.getFactory().create(BoundImportDataDirectory.class);
        boundImportDataDirectory.initBoundImportDataDirectory(ntHeader, reader);
        return boundImportDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public BoundImportDataDirectory() {}

	private void initBoundImportDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);

        if (descriptors == null) descriptors = new BoundImportDescriptor[0];
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(NAME, 0);
        for (BoundImportDescriptor descriptor : descriptors) {
            struct.add(descriptor.toDataType());
        }
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }

	/**
	 * Returns the array of bound import descriptors defined in this bound import data directory.
	 * @return the array of bound import descriptors defined in this bound import data directory
	 */
    public BoundImportDescriptor [] getBoundImportDescriptors() {
        return descriptors;
    }

    @Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException {

    	monitor.setMessage(program.getName()+": bound import(s)...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		for (BoundImportDescriptor descriptor : descriptors) {
            if (monitor.isCancelled()) {
                return;
            }
            DataType dt = descriptor.toDataType();
			PeUtils.createData(program, addr, dt, log);
            addr = addr.add(dt.getLength());

            long namePtr = descriptor.getOffsetModuleName()+virtualAddress;
            Address nameAddr = space.getAddress(va(namePtr, isBinary));
            createTerminatedString(program, nameAddr, false, log);
        }

		BoundImportDescriptor terminator = new BoundImportDescriptor();
		PeUtils.createData(program, addr, terminator.toDataType(), log);
    }

    @Override
    public String getDirectoryName() {
    	return NAME;
    }

    @Override
	public boolean parse() throws IOException {
    	nameHash = new LinkedHashMap<String,Short>();
    	
        int rva = getVirtualAddress();
        int ptr = getVirtualAddress();
        if (rva <= 0) {
        	if (rva < 0) {
        		Msg.error(this, "Invalid RVA "+rva);
        	}
        	return false;
        }

        List<BoundImportDescriptor> descriptorsList = new ArrayList<BoundImportDescriptor>();
        while (true) {
        	if (ptr < 0) { 
            	Msg.error(this, "Invalid file index "+ptr);
            	break;
        	}
            BoundImportDescriptor bid = BoundImportDescriptor.createBoundImportDescriptor(reader, ptr, rva);

            if (bid.getTimeDateStamp() == 0) break;
            if (bid.getNumberOfModuleForwarderRefs() < 0) break;

            descriptorsList.add(bid);

            // increment ptr by 1 BoundImportDescriptor and
            // the number of forwards refs located
            //
            ptr += BoundImportDescriptor.IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR;
            ptr += (bid.getNumberOfModuleForwarderRefs() * BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF);
        }

        descriptors = new BoundImportDescriptor[descriptorsList.size()];
        descriptorsList.toArray(descriptors);

		buildNameHash();
		return true;
    }

	@Override
    int rvaToPointer() {
		return virtualAddress;
	}

	@Override
    public void writeBytes(RandomAccessFile raf, DataConverter dc, PortableExecutable template) throws IOException {
		if (size == 0) {
			return;
		}

		//this is the actual byte position in the file
		raf.seek(rvaToPointer());

		//write the descriptors...
		for (BoundImportDescriptor descriptor : descriptors) {
			raf.write(dc.getBytes(descriptor.getTimeDateStamp()));
			raf.write(dc.getBytes(descriptor.getOffsetModuleName()));
			raf.write(dc.getBytes(descriptor.getNumberOfModuleForwarderRefs()));
			for (int j = 0 ; j < descriptor.getNumberOfModuleForwarderRefs() ; ++j) {
				BoundImportForwarderRef forwarder = descriptor.getBoundImportForwarderRef(j);
				raf.write(dc.getBytes(forwarder.getTimeDateStamp()));
				raf.write(dc.getBytes(forwarder.getOffsetModuleName()));
				raf.write(dc.getBytes(forwarder.getReserved()));
			}
		}

		int zeroInt = 0;
		short zeroShort = 0;

		//write a terminating descriptor...
		raf.write(dc.getBytes(zeroInt));
		raf.write(dc.getBytes(zeroShort));
		raf.write(dc.getBytes(zeroShort));

		//write the dll names...
		Iterator<String> iter = nameHash.keySet().iterator();
		short prevOffset = 0;
		while (iter.hasNext()) {
			String name = iter.next();
			Short currOffset = nameHash.get(name);
			if (currOffset.shortValue() < prevOffset) {
				throw new IllegalArgumentException();
			}
			prevOffset = currOffset.shortValue();

			raf.write(name.getBytes());
			raf.write((byte)0);//null-terminator
		}
	}

	void updatePointers(int offset) {
		virtualAddress += offset;
	}

	public void addDescriptor(BoundImportDescriptor bid) {
		BoundImportDescriptor [] tmp = new BoundImportDescriptor[descriptors.length+1];
		System.arraycopy(descriptors, 0, tmp, 0, descriptors.length);
		tmp[tmp.length-1] = bid;
		descriptors = tmp;

		size +=  BoundImportDescriptor.IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR;
		size += (bid.getNumberOfModuleForwarderRefs() * BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF);
		size += (bid.getModuleName().length() + 1);

		buildNameHash();
	}

	private void buildNameHash() {
		nameHash.clear();

		int pos = (descriptors.length + 1) * BoundImportDescriptor.IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR;
		for (BoundImportDescriptor descriptor : descriptors) {
			pos += (descriptor.getNumberOfModuleForwarderRefs() * BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF);
		}

		for (BoundImportDescriptor descriptor : descriptors) {
			Short offset = nameHash.get(descriptor.getModuleName());
			if (offset != null) {
				descriptor.setOffsetModuleName(offset.shortValue());
			}
			else {
				String moduleName = descriptor.getModuleName();
				if (moduleName != null && moduleName.length() > 0) {
					nameHash.put(moduleName, new Short((short)pos));
					descriptor.setOffsetModuleName((short)pos);
					pos += (descriptor.getModuleName().length() + 1);
				}
			}
			
			for (int j = 0 ; j < descriptor.getNumberOfModuleForwarderRefs() ; ++j) {
				BoundImportForwarderRef forwarder = descriptor.getBoundImportForwarderRef(j);
				if (forwarder == null) {
					continue;
				}
				offset = nameHash.get(forwarder.getModuleName());
				if (offset != null) {
					forwarder.setOffsetModuleName(offset.shortValue());
				}
				else {
					String moduleName = forwarder.getModuleName();
					if (moduleName != null && moduleName.length() > 0) {
						nameHash.put(moduleName, new Short((short)pos));
						forwarder.setOffsetModuleName((short)pos);
						pos += (forwarder.getModuleName().length() + 1);
					}
				}
			}
		}
	}
}
