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
package ghidra.file.formats.dtb;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * Class to represent a Flattened Device Tree (FDT) Header. 
 *
 */
public class FdtHeader implements StructConverter {

	private static final int OFF_DT_STRUCT_INDEX = 2;
	private static final int OFF_DT_STRINGS_INDEX = 3;
	private static final int OFF_MEM_RSVMAP_INDEX = 4;

	private int magic;
	private int totalsize;
	private int off_dt_struct;
	private int off_dt_strings;
	private int off_mem_rsvmap;
	private int version;
	private int last_comp_version;
	/* version 2 fields below */
	private int boot_cpuid_phys;
	/* version 3 fields below */
	private int size_dt_strings;
	/* version 17 fields below */
	private int size_dt_struct;

	private Map<Integer, String> stringsMap = new HashMap<>();

	public FdtHeader(BinaryReader reader) throws IOException {
		if (!reader.isBigEndian()) {
			throw new IOException("FTD is always big endian.");
		}

		magic = reader.readNextInt();

		if (magic != FdtConstants.FDT_MAGIC) {
			throw new IOException("Invalid FDT Header magic.");
		}

		totalsize = reader.readNextInt();
		off_dt_struct = reader.readNextInt();
		off_dt_strings = reader.readNextInt();
		off_mem_rsvmap = reader.readNextInt();
		version = reader.readNextInt();
		last_comp_version = reader.readNextInt();

		if (version >= FdtConstants.FDT_VERSION_2) {
			boot_cpuid_phys = reader.readNextInt();
		}
		if (version >= FdtConstants.FDT_VERSION_3) {
			size_dt_strings = reader.readNextInt();
		}
		if (version == FdtConstants.FDT_VERSION_17) {
			size_dt_struct = reader.readNextInt();
		}
		if (version > FdtConstants.FDT_VERSION_17) {
			throw new IOException("Unsupported FDT Header version: " + version);
		}
	}

	/**
	 * Returns the MAGIC value of this FDT Header.
	 * @see FdtConstants.MAGIC.
	 * @return the MAGIC value of this FDT Header
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * Returns the total size of this FDT, including all sub-structures.
	 * @return the total size of this FDT, including all sub-structures
	 */
	public int getTotalSize() {
		return totalsize;
	}

	/**
	 * Returns the offset to the Device Tree (DT) structure.
	 * @return the offset to the Device Tree (DT) structure
	 */
	public int getOffsetToDtStruct() {
		return off_dt_struct;
	}

	/**
	 * Returns the offset to the Device Tree (DT) strings.
	 * @return the offset to the Device Tree (DT) strings
	 */
	public int getOffsetToDtStrings() {
		return off_dt_strings;
	}

	/**
	 * Returns the offset to the Device Tree (DT) memory reserve map.
	 * @return the offset to the Device Tree (DT) memory reserve map
	 */
	public int getOffsetToMemoryReserveMap() {
		return off_mem_rsvmap;
	}

	/**
	 * Returns the Device Tree (DT) version.
	 * @return the Device Tree (DT) version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns the last compatible Device Tree (DT) version.
	 * @return the last compatible Device Tree (DT) version
	 */
	public int getLastCompatibleVersion() {
		return last_comp_version;
	}

	/**
	 * Returns the Boot CPU ID.
	 * @return the Boot CPU ID
	 */
	public int getBootCpuIdPhysical() {
		return boot_cpuid_phys;
	}

	/**
	 * Returns the Device Tree (DT) strings size.
	 * @return the Device Tree (DT) strings size
	 */
	public int getSizeDtStrings() {
		return size_dt_strings;
	}

	/**
	 * Returns the Device Tree (DT) structure size.
	 * @return the Device Tree (DT) structure size
	 */
	public int getSizeDtStruct() {
		return size_dt_struct;
	}

	/**
	 * Marks up the program containing this FDT.
	 * @param fdtHeaderAddress the address where the FDT starts
	 * @param program the program to markup
	 * @param monitor the TaskMonitor
	 * @param log the MessageLog
	 * @throws Exception if an exception occurs
	 */
	public void markup(Address fdtHeaderAddress, Program program,
			TaskMonitor monitor,
			MessageLog log) throws Exception {

		FlatProgramAPI programAPI = new FlatProgramAPI(program);

		DataType fdtHeaderDataType = this.toDataType();
		Data fdtHeaderData = program.getListing().createData(fdtHeaderAddress, fdtHeaderDataType);
		programAPI.createFragment(fdtHeaderData.getDataType().getName(), fdtHeaderAddress,
			fdtHeaderData.getLength());

		//process strings first, so we can use them for the structure
		markupStrings(fdtHeaderAddress, fdtHeaderData, programAPI, monitor);
		markupStructure(fdtHeaderAddress, fdtHeaderData, programAPI, monitor);
		markupMemoryReserveMap(fdtHeaderAddress, fdtHeaderData, programAPI, monitor);
	}

	private void markupStructure(Address fdtHeaderAddress,
			Data fdtHeaderData,
			FlatProgramAPI programAPI, TaskMonitor monitor)
			throws IOException, DuplicateNameException, CodeUnitInsertionException,
			NotFoundException {

		Address structAddress = fdtHeaderAddress.add(getOffsetToDtStruct());
		Data structsData = fdtHeaderData.getComponent(OFF_DT_STRUCT_INDEX);
//		program.getReferenceManager()
//				.addMemoryReference(structsData.getMinAddress(),
//					structAddress, RefType.DATA,
//					SourceType.ANALYSIS, 0);

		programAPI.createMemoryReference(structsData, structAddress, RefType.DATA);

		markupStructureContents(structAddress, programAPI, monitor);
	}

	private void markupStructureContents(Address address, FlatProgramAPI programAPI,
			TaskMonitor monitor)
			throws IOException, DuplicateNameException, CodeUnitInsertionException,
			NotFoundException {

		Program currentProgram = programAPI.getCurrentProgram();
		ByteProvider provider =
			new MemoryByteProvider(currentProgram.getMemory(), address);
		BinaryReader reader =
			new BinaryReader(provider, !currentProgram.getLanguage().isBigEndian());

		while (!monitor.isCancelled()) {
			DWordDataType dWordDataType = new DWordDataType();
			switch (reader.peekNextInt()) {
				case FdtConstants.FDT_BEGIN_NODE: {
					FdtNodeHeader nodeHeader = new FdtNodeHeader(reader);
					DataType nodeHeaderDataType = nodeHeader.toDataType();
					programAPI.createData(address, nodeHeaderDataType);
					programAPI.createFragment("FDT_BEGIN_NODE", address,
						nodeHeaderDataType.getLength());
					programAPI.setPlateComment(address,
						"FDT_BEGIN_NODE" + ": " + nodeHeader.getName());
					address = address.add(nodeHeaderDataType.getLength());
					break;
				}
				case FdtConstants.FDT_END_NODE: {
					reader.readNextInt();
					programAPI.createData(address, dWordDataType);
					programAPI.createFragment("FDT_END_NODE", address,
						dWordDataType.getLength());
					programAPI.setPlateComment(address, "FDT_END_NODE");
					address = address.add(4);
					break;
				}
				case FdtConstants.FDT_PROP: {
					FdtProperty property = new FdtProperty(reader);
					DataType propertyDataType = property.toDataType();
					programAPI.createData(address, propertyDataType);
					programAPI.createFragment("FDT_PROP", address,
						propertyDataType.getLength());
					programAPI.setPlateComment(address,
						"FDT_PROP" + ": \n" + getString(property) + " = " +
							property.getDataAsString());
					address = address.add(propertyDataType.getLength());
					break;
				}
				case FdtConstants.FDT_NOP: {
					reader.readNextInt();
					programAPI.createData(address, dWordDataType);
					programAPI.createFragment("FDT_NOP", address,
						dWordDataType.getLength());
					programAPI.setPlateComment(address, "FDT_NOP");
					address = address.add(4);
					break;
				}
				case FdtConstants.FDT_END: {
					reader.readNextInt();
					programAPI.createData(address, dWordDataType);
					programAPI.createFragment("FDT_END", address,
						dWordDataType.getLength());
					programAPI.setPlateComment(address, "FDT_END");
					address = address.add(4);
					return;
				}
			}
		}
	}

	private void markupStrings(Address fdtHeaderAddress, Data fdtHeaderData,
			FlatProgramAPI programAPI, TaskMonitor monitor) throws Exception {

		Address stringsAddress = fdtHeaderAddress.add(getOffsetToDtStrings());
		Data stringsData = fdtHeaderData.getComponent(OFF_DT_STRINGS_INDEX);
		programAPI.createMemoryReference(stringsData, stringsAddress, RefType.DATA);

		int stringSize = 0;
		while (!monitor.isCancelled()) {
			Data stringData = programAPI.createData(stringsAddress, StringDataType.dataType);
			programAPI.createFragment(StringDataType.dataType.getName(), stringsAddress,
				stringData.getLength());
			String string = (String) stringData.getValue();
			storeString(fdtHeaderAddress, stringsAddress, string);
			stringsAddress = stringsAddress.add(stringData.getLength());
			stringSize += stringData.getLength();
			if (stringSize >= getSizeDtStrings()) {
				break;
			}
		}
	}

	private void markupMemoryReserveMap(Address fdtHeaderAddress, Data fdtHeaderData,
			FlatProgramAPI programAPI, TaskMonitor monitor) {

		Address structAddress = fdtHeaderAddress.add(getOffsetToMemoryReserveMap());
		Data structsData = fdtHeaderData.getComponent(OFF_MEM_RSVMAP_INDEX);
		programAPI.createMemoryReference(structsData, structAddress, RefType.DATA);
	}

	private void storeString(Address fdtHeaderAddress, Address stringsAddress, String string) {
		long index = stringsAddress.getOffset() - fdtHeaderAddress.getOffset() - off_dt_strings;
		stringsMap.put((int) index, string);
	}

	/**
	 * Look up the string for this property.
	 */
	private String getString(FdtProperty property) {
		return stringsMap.getOrDefault(property.getNameOffset(), "");
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = new StructureDataType("fdt_header", 0);
		structure.add(DWORD, "magic", null);
		structure.add(DWORD, "totalsize", null);
		structure.add(DWORD, "off_dt_struct", null);
		structure.add(DWORD, "off_dt_strings", null);
		structure.add(DWORD, "off_mem_rsvmap", null);
		structure.add(DWORD, "version", null);
		structure.add(DWORD, "last_comp_version", null);

		if (version >= FdtConstants.FDT_VERSION_2) {
			structure.add(DWORD, "boot_cpuid_phys", null);
		}
		if (version >= FdtConstants.FDT_VERSION_3) {
			structure.add(DWORD, "size_dt_strings", null);
		}
		if (version >= FdtConstants.FDT_VERSION_17) {
			structure.add(DWORD, "size_dt_struct", null);
		}
		return structure;
	}
}
