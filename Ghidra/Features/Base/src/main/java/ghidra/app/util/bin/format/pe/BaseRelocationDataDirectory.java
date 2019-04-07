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

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Points to the base relocation information.
 */
public class BaseRelocationDataDirectory extends DataDirectory implements ByteArrayConverter {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_BASERELOC";

    private BaseRelocation [] relocs;

    static BaseRelocationDataDirectory createBaseRelocationDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        BaseRelocationDataDirectory baseRelocationDataDirectory = (BaseRelocationDataDirectory) reader.getFactory().create(BaseRelocationDataDirectory.class);
        baseRelocationDataDirectory.initBaseRelocationDataDirectory(ntHeader, reader);
        return baseRelocationDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public BaseRelocationDataDirectory() {}

	private void initBaseRelocationDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
        if (relocs == null) relocs = new BaseRelocation[0];
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws CodeUnitInsertionException {

		monitor.setMessage(program.getName()+": base relocation(s)...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);

        for (BaseRelocation reloc : relocs) {
            if (monitor.isCancelled()) {
                return;
            }

			PeUtils.createData(program, addr, DWORD, log);
            addr = addr.add(DWORD.getLength());

			PeUtils.createData(program, addr, DWORD, log);
            addr = addr.add(DWORD.getLength());

            int count = reloc.getCount();
            for (int j = 0 ; j < count ; ++j) {
                if (monitor.isCancelled()) {
                    return;
                }
				PeUtils.createData(program, addr, WORD, log);
               	addr = addr.add(WORD.getLength());
            }
        }
	}

	@Override
	public boolean parse() throws IOException {
		int addr = getPointer();
		if (addr < 0) {
			return false;
		}
        int stop = addr + getSize();

        List<BaseRelocation> relocsList = new ArrayList<BaseRelocation>();

        while (true) {
            if (addr >= stop) break;

            BaseRelocation br = BaseRelocation.createBaseRelocation(reader, addr);

            // Sanity check to make sure the data looks OK.
            if (br.getVirtualAddress() == 0)
                break;
            if (br.getSizeOfBlock() < BaseRelocation.IMAGE_SIZEOF_BASE_RELOCATION)
                break;
            if (br.getSizeOfBlock() == 0)
                break;

            relocsList.add(br);
            addr += br.getSizeOfBlock();
        }

        relocs = new BaseRelocation[relocsList.size()];
        relocsList.toArray(relocs);
        return true;
    }

	/**
	 * Returns the array of base relocations defined in this base relocation data directory.
	 * @return the array of base relocations defined in this base relocation data directory
	 */
    public BaseRelocation [] getBaseRelocations() {
        return relocs;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, 0);
        for (BaseRelocation reloc : relocs) {
            struct.add(reloc.toDataType());
        }
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }

	/**
	 * Removes all base relocations from this base relocation
	 * directory.
	 */
	public void removeAllRelocations() {
		relocs = new BaseRelocation[0];
		size = 0;
	}

	/**
	 * Create a new base relocation using the specified
	 * virtual address.
	 * @param va the virtual address of the new base relocation
	 * @return the new base relocation
	 */
	public BaseRelocation createBaseRelocation(int va) {
		return new BaseRelocation(va);
	}

	/**
	 * Adds the specified base relocation.
	 * @param reloc the new base relocation
	 */
	public void addBaseRelocation(BaseRelocation reloc) {
		size += reloc.getSizeOfBlock();

		BaseRelocation [] tmp = new BaseRelocation[relocs.length+1];
		System.arraycopy(relocs, 0, tmp, 0, relocs.length);
		tmp[tmp.length-1] = reloc;
		relocs = tmp;
	}

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	public byte[] toBytes(DataConverter dc) {
		int lsize = 0;
		for (BaseRelocation reloc : relocs) {
			lsize += reloc.getSizeOfBlock();
		}

		byte [] bytes = new byte[lsize];
		int pos = 0;
		for (BaseRelocation reloc : relocs) {
			byte [] relocBytes = reloc.toBytes(dc);
			System.arraycopy(relocBytes, 0, bytes, pos, relocBytes.length);
			pos += relocBytes.length;
		}

		return bytes;
	}

}
