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
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Points to the imports (an array of IMAGE_IMPORT_DESCRIPTOR structures).
 */
public class ImportDataDirectory extends DataDirectory {
	private final static String NAME = "IMAGE_DIRECTORY_ENTRY_IMPORT";

	private ImportDescriptor[] descriptors;
	private ImportInfo[] imports;

	ExportDataDirectory exportDirectory;
	DataConverter conv = LittleEndianDataConverter.INSTANCE;

	static ImportDataDirectory createImportDataDirectory(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader) throws IOException {
		ImportDataDirectory importDataDirectory =
			(ImportDataDirectory) reader.getFactory().create(ImportDataDirectory.class);
		importDataDirectory.initImportDataDirectory(ntHeader, reader);
		return importDataDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ImportDataDirectory() {
	}

	private void initImportDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
			throws IOException {
		processDataDirectory(ntHeader, reader);

		if (imports == null) {
			imports = new ImportInfo[0];
		}
		if (descriptors == null) {
			descriptors = new ImportDescriptor[0];
		}
	}

	/**
	 * Returns the array of ImportInfo defined in this import directory.
	 * @return the array of ImportInfo defined in this import directory
	 */
	public ImportInfo[] getImports() {
		return imports;
	}

	/**
	 * Returns the array of ImportDescriptor defined in this import directory.
	 * @return the array of ImportDescriptor defined in this import directory
	 */
	public ImportDescriptor[] getImportDescriptors() {
		return descriptors;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException, MemoryAccessException {

		if (imports == null || descriptors == null) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: import(s)...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);

		TerminatedStringDataType tsdt = new TerminatedStringDataType();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		for (ImportDescriptor descriptor : descriptors) {//markup the import descriptor(s)...
			if (monitor.isCancelled()) {
				break;
			}

			setPlateComment(program, addr, ImportDescriptor.NAME);
			for (int j = 0; j < 5; ++j) {
				PeUtils.createData(program, addr, DWORD, log);
				addr = addr.add(DWORD.getLength());
			}

			if (descriptor.getName() == 0 && descriptor.getTimeDateStamp() == 0) {
				continue;
			}

			String dll = descriptor.getDLL();
			if (dll != null && dll.startsWith(program.getName())) {
				Msg.warn(this,
					program.getName() + " potentially modified via import of local exports");
				DataDirectory[] dataDirectories = ntHeader.getOptionalHeader().getDataDirectories();
				exportDirectory =
					(ExportDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT];
			}

			long nameAddr = va(descriptor.getName(), isBinary);

			Address nameAddress = space.getAddress(nameAddr);
			setPlateComment(program, nameAddress, ImportDescriptor.NAME + " - DLL NAME");
			PeUtils.createData(program, nameAddress, tsdt, log);

			int intptr =
				descriptor.getOriginalFirstThunk() != 0 ? descriptor.getOriginalFirstThunk()
						: descriptor.getFirstThunk();

			int iatptr = descriptor.getFirstThunk();

			ThunkData[] thunks = descriptor.getImportNameTableThunkData();
			for (int j = 0; j < thunks.length; ++j) {
				if (monitor.isCancelled()) {
					break;
				}

				try {
					markupINT(intptr, iatptr, isBinary, program, thunks[j], log);
					markupIAT(iatptr, isBinary, program, log);
				}
				catch (MemoryAccessException mae) {
					Msg.error(this,
						"Invalid memory access for iaptr " + Integer.toHexString(iatptr));
					break;
				}

				// OK, this is kind of a hack and maybe unnecessary, but it adds some value in the import-of-export case
				if (descriptor.getDLL().startsWith(program.getName())) {
					ExportInfo exportInfo = exportDirectory.getExports()[j];
					long address = exportInfo.getAddress();
					long thunkAddr = va(intptr, isBinary);
					byte[] bytes = ntHeader.getOptionalHeader().is64bit() ? conv.getBytes(address)
							: conv.getBytes((int) address);
					try {
						program.getMemory().setBytes(
							program.getImageBase().getAddress(Long.toHexString(thunkAddr)), bytes);
					}
					catch (AddressFormatException e) {
						Msg.warn(this, "Unable to convert " + thunkAddr);
					}
				}

				intptr += thunks[j].getStructSize();
				iatptr += thunks[j].getStructSize();

				ImportByName ibn = thunks[j].getImportByName();
				if (!thunks[j].isOrdinal() && ibn != null) {
					long ibnAddr = va(thunks[j].getAddressOfData(), isBinary);
					Address ibnAddress = space.getAddress(ibnAddr);
					setPlateComment(program, ibnAddress, ImportByName.NAME);
					PeUtils.createData(program, ibnAddress, WORD, log);
					Address ibnNameAddress = ibnAddress.add(WORD.getLength());
					PeUtils.createData(program, ibnNameAddress, tsdt, log);
				}

			}
		}
	}

	private void markupIAT(int iatptr, boolean isBinary, Program program, MessageLog log)
			throws MemoryAccessException {
		DataType dt = null;
		if (isBinary) {
			dt = ntHeader.getOptionalHeader().is64bit() ? (DataType) QWORD : (DataType) DWORD;
		}
		else {
			dt = PointerDataType.getPointer(null, -1);
		}
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		long thunkAddr = va(iatptr, isBinary);
		Address thunkAddress = space.getAddress(thunkAddr);
		if (program.getMemory().getInt(thunkAddress) != 0) {
			PeUtils.createData(program, thunkAddress, dt, log);
		}
	}

	private void markupINT(int intptr, int iatptr, boolean isBinary, Program program,
			ThunkData thunk, MessageLog log) {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		long thunkAddr = va(intptr, isBinary);
		Address thunkAddress = space.getAddress(thunkAddr);
		setEolComment(program, thunkAddress, thunk.getStructName());

		DataType dt = null;
		if (intptr == iatptr && !isBinary) {
			dt = PointerDataType.getPointer(null, program.getMinAddress().getPointerSize());
		}
		else {
			dt = ntHeader.getOptionalHeader().is64bit() ? (DataType) QWORD : (DataType) DWORD;
		}
		PeUtils.createData(program, thunkAddress, dt, log);
	}

	@Override
	public boolean parse() throws IOException {
		List<ImportInfo> importList = new ArrayList<>();
		List<ImportDescriptor> descriptorsList = new ArrayList<>();

		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}

		ImportDescriptor id = ImportDescriptor.createImportDescriptor(reader, ptr);
		while (!id.isNullEntry()) {

			ptr += ImportDescriptor.SIZEOF;
			if (descriptorsList.size() > NTHeader.MAX_SANE_COUNT) {
				Msg.error(this, "Too many import descriptors");
				return false;
			}
			descriptorsList.add(id);

			if (id.getName() == 0 && id.getTimeDateStamp() == 0) {
				break;
			}

			int tmpPtr = ntHeader.rvaToPointer(id.getName());
			if (tmpPtr < 0) {
				//Msg.error(this, "Invalid RVA "+id.getName());
				id = ImportDescriptor.createImportDescriptor(reader, ptr);
				continue;
			}
			String dllName = reader.readAsciiString(tmpPtr);
			id.setDLL(dllName);

			if (id.getOriginalFirstThunk() == 0 && id.getFirstThunk() == 0) {
				return false;
			}

			int intptr = -1;
			if (id.getOriginalFirstThunk() != 0) {
				intptr = ntHeader.rvaToPointer(id.getOriginalFirstThunk());
			}
			if (intptr < 0) {
				intptr = ntHeader.rvaToPointer(id.getFirstThunk());
			}
			if (intptr < 0) {
				Msg.error(this, "Invalid RVA " + Integer.toHexString(id.getOriginalFirstThunk()) +
					" : " + Integer.toHexString(id.getFirstThunk()));
				id = ImportDescriptor.createImportDescriptor(reader, ptr);
				return false;
			}
			int iatptr = ntHeader.rvaToPointer(id.getFirstThunk());

			int nextPosToCreateExternalRef = 0;
			while (true) {
				if (!ntHeader.checkPointer(intptr)) {
					Msg.error(this, "Invalid file index " + Integer.toHexString(intptr));
					break;
				}
				if (!ntHeader.checkPointer(iatptr)) {
					Msg.error(this, "Invalid file index " + Integer.toHexString(iatptr));
					break;
				}

				ThunkData intThunk = ThunkData.createThunkData(reader, intptr,
					ntHeader.getOptionalHeader().is64bit());
				intptr += intThunk.getStructSize();

				ThunkData iatThunk = ThunkData.createThunkData(reader, iatptr,
					ntHeader.getOptionalHeader().is64bit());
				iatptr += iatThunk.getStructSize();

				if (intThunk.getAddressOfData() == 0) {
					break;
				}
				id.addImportNameTableThunkData(intThunk);
				id.addImportAddressTableThunkData(iatThunk);

				int addr = id.getFirstThunk() + nextPosToCreateExternalRef;
				nextPosToCreateExternalRef += intThunk.getStructSize();

				String boundName = null;
				long ordinal = -1;

				if (intThunk.isOrdinal()) {
					ordinal = intThunk.getOrdinal();
					String ordinalStr = "Ordinal" + "_" + ordinal;
					boundName = ordinalStr;
				}
				else {
					// retrieve the IMAGE_IMPORT_BY_NAME struct, but do so in pieces
					int ptrToData = ntHeader.rvaToPointer((int) intThunk.getAddressOfData());
					if (ptrToData < 0) {
						Msg.error(this,
							"Invalid RVA " + Long.toHexString(intThunk.getAddressOfData()));
						break;
					}
					ImportByName ibn = ImportByName.createImportByName(reader, ptrToData);

					intThunk.setImportByName(ibn);

					boundName = ibn.getName();
					ordinal = ibn.getHint();
				}

				StringBuffer cmt = new StringBuffer();
				if (ordinal != -1) {
					cmt.append(Long.toString(ordinal) + "  ");
				}
				if (boundName != null) {
					cmt.append(boundName + "  ");
				}
				if (id.isBound()) {
					long boundAddr = iatThunk.getAddressOfData();
					cmt.append("[Bound to: 0x" + Long.toHexString(boundAddr) + "]");
				}
				else {
					cmt.append("<<not bound>>");
				}
				if (importList.size() > NTHeader.MAX_SANE_COUNT) {
					Msg.error(this, "Too many imports");
					return false;
				}
				importList.add(
					new ImportInfo(addr, cmt.toString(), dllName, boundName, id.isBound()));
			}
			id = ImportDescriptor.createImportDescriptor(reader, ptr);
		}

		imports = new ImportInfo[importList.size()];
		importList.toArray(imports);

		descriptors = new ImportDescriptor[descriptorsList.size()];
		descriptorsList.toArray(descriptors);
		return true;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();
		buff.append("\t\t" + "Import Directory: [" + super.toString() + "]" + "\n");
		for (ImportInfo info : imports) {
			buff.append("\t\t\t" + "0x" + Long.toHexString(info.getAddress()) + "  " +
				info.getDLL() + " " + info.getName() + "\n");
		}
		return buff.toString();
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		DataType array = new ArrayDataType(BYTE, size, 1);
		struct.add(array, array.getLength(), "IMPORT", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
