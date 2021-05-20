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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pdb.PdbInfoCodeView;
import ghidra.app.util.bin.format.pdb.PdbInfoDotNet;
import ghidra.app.util.bin.format.pe.debug.*;
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
 * Points to an array of IMAGE_DEBUG_DIRECTORY structures.
 */
public class DebugDataDirectory extends DataDirectory {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_DEBUG";

    private DebugDirectoryParser parser;

    static DebugDataDirectory createDebugDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        DebugDataDirectory debugDataDirectory = (DebugDataDirectory) reader.getFactory().create(DebugDataDirectory.class);
        debugDataDirectory.initDebugDataDirectory(ntHeader, reader);
        return debugDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DebugDataDirectory() {}

	private void initDebugDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
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
		
    	parser = DebugDirectoryParser.createDebugDirectoryParser(reader, ptr, size, ntHeader);
    	return true;
    }

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {

		monitor.setMessage(program.getName()+": debug...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		DebugDirectory [] ddarr = parser.getDebugDirectories();
		for (DebugDirectory dd : ddarr) {
			PeUtils.createData(program, addr, dd.toDataType(), log);
			addr = addr.add(DebugDirectory.IMAGE_SIZEOF_DEBUG_DIRECTORY);

			Address dataAddr = getDataAddress(dd, isBinary, space, ntHeader);
			if (dataAddr != null) {
				boolean success = createFragment(program, "Debug Data", dataAddr, dataAddr.add(dd.getSizeOfData()));
				if (!success) {
					log.appendMsg("Unable to create fragment: Debug Data");
				}
			}
		}

		markupDebigMisc(program, isBinary, log, space);
		markupDebugCodeView(program, isBinary, log, space);
	}

	private void markupDebugCodeView(Program program, boolean isBinary,
			MessageLog log, AddressSpace space) throws DuplicateNameException, IOException {
		DebugCodeView dcv = parser.getDebugCodeView();
		if (dcv != null) {
			Address dataAddr = getDataAddress(dcv.getDebugDirectory(), isBinary, space, ntHeader);
			if (dataAddr != null) {
				PdbInfoCodeView pdbInfo = dcv.getPdbInfo();
				if (pdbInfo != null) {
					setPlateComment(program, dataAddr, "CodeView PDB Info");
					PeUtils.createData(program, dataAddr, pdbInfo.toDataType(), log);
				}
				PdbInfoDotNet dotNetPdbInfo = dcv.getDotNetPdbInfo();
				if (dotNetPdbInfo != null) {
					setPlateComment(program, dataAddr, ".NET PDB Info");
					PeUtils.createData(program, dataAddr, dotNetPdbInfo.toDataType(), log);
				}
			}
		}
	}

	private void markupDebigMisc(Program program, boolean isBinary,
			MessageLog log, AddressSpace space) throws DuplicateNameException {
		DebugMisc dm = parser.getDebugMisc();
		if (dm != null) {
			Address dataAddr = getDataAddress(dm.getDebugDirectory(), isBinary, space, ntHeader);
			if (dataAddr != null) {
				setPlateComment(program, dataAddr, "Misc Debug Info");
				PeUtils.createData(program, dataAddr, dm.toDataType(), log);
			}
		}
	}

    private Address getDataAddress(DebugDirectory dd, boolean isBinary,
						AddressSpace space, NTHeader ntHeader) {

		long ptr = 0;
		if (isBinary) {
			ptr = dd.getPointerToRawData();
	        if (ptr != 0 && !ntHeader.checkPointer(ptr)) {
	        	Msg.error(this, "Invalid pointer "+Long.toHexString(ptr));
	        	return null;
	        }
		}
		else {
			ptr = dd.getAddressOfRawData();
		}
		if (ptr != 0) {
			if (isBinary) {
				return space.getAddress(ptr);
			}
			return space.getAddress(ptr + ntHeader.getOptionalHeader().getImageBase());
		}
		return null;
	}

	/**
     * Returns the debug parser used by this debug directory.
     * @return the debug parser used by this debug directory
     */
	public DebugDirectoryParser getParser() {
		return parser;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(NAME, 0);
        DebugDirectory [] ddArr = parser.getDebugDirectories();
        for (DebugDirectory sc : ddArr) {
            struct.add(sc.toDataType(),sc.getDescription(),null );
        }
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }

	/**
	 * @see ghidra.app.util.bin.format.pe.DataDirectory#writeBytes(java.io.RandomAccessFile, ghidra.util.DataConverter, ghidra.app.util.bin.format.pe.PortableExecutable)
	 */
	@Override
    public void writeBytes(RandomAccessFile raf, DataConverter dc, PortableExecutable template) 
		throws IOException {
		OptionalHeader optionalHeader = template.getNTHeader().getOptionalHeader();
		DataDirectory [] originalDataDirs = optionalHeader.getDataDirectories();
		if (optionalHeader.getNumberOfRvaAndSizes() <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG) {
			return;
		}
		if (originalDataDirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG] == null || 
			originalDataDirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG].getSize() == 0) {
			return;
		}
		DebugDataDirectory templateDDD = (DebugDataDirectory) template.getNTHeader().getOptionalHeader().getDataDirectories()[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG];
		DebugDirectory [] templateDD = templateDDD.getParser().getDebugDirectories();
		DebugDirectory [] dd = parser.getDebugDirectories();
		for (int i = 0; i < dd.length; i++) {
			dd[i].writeHeader(raf, dc);

			if (dd[i].getSizeOfData() == 0 || dd[i].getPointerToRawData() == 0) {
				continue;
			}

			int ptr = dd[i].getPointerToRawData();
	        if (!ntHeader.checkPointer(ptr)) {
	        	Msg.error(this, "Invalid pointer "+Long.toHexString(ptr));
	        	continue;
	        }
			raf.seek(ptr);
			raf.write(templateDD[i].toBytes(dc));
		}	
	}
	
	void updatePointers(int offset, int postOffset) {
		DebugDirectory [] debugDirs = parser.getDebugDirectories();
		for (DebugDirectory debugDir : debugDirs) {
			if (debugDir.getSizeOfData() == 0 || debugDir.getPointerToRawData() == 0) {
				continue;
			}
			debugDir.updatePointers(offset, postOffset);
		}
	}
}
