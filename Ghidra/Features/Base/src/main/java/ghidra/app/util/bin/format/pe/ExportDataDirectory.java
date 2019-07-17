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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * A class to represent the <code>IMAGE_EXPORT_DIRECTORY</code>
 * data structure defined in <b><code>winnt.h</code></b>.
 * <pre>
 * typedef struct _IMAGE_EXPORT_DIRECTORY {
 *     DWORD   Characteristics;
 *     DWORD   TimeDateStamp;
 *     WORD    MajorVersion;
 *     WORD    MinorVersion;
 *     DWORD   Name;
 *     DWORD   Base;
 *     DWORD   NumberOfFunctions;
 *     DWORD   NumberOfNames;
 *     DWORD   AddressOfFunctions;     // RVA from base of image
 *     DWORD   AddressOfNames;         // RVA from base of image
 *     DWORD   AddressOfNameOrdinals;  // RVA from base of image
 * };
 * </pre>
 */
public class ExportDataDirectory extends DataDirectory {
	private final static String NAME = "IMAGE_DIRECTORY_ENTRY_EXPORT";
	/**
	 * The size of the <code>IMAGE_EXPORT_DIRECTORY</code> in bytes.
	 */
	public final static int IMAGE_SIZEOF_EXPORT_DIRECTORY = 40;

	private int characteristics;
	private int timeDateStamp;
	private short majorVersion;
	private short minorVersion;
	private int name;
	private int base;
	private int numberOfFunctions;
	private int numberOfNames;
	private int addressOfFunctions;
	private int addressOfNames;
	private int addressOfNameOrdinals;

	private int exportsStartRVA;
	private int exportsEndRVA;

	private ExportInfo[] exports;

	private String exportName;

	static ExportDataDirectory createExportDataDirectory(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader) throws IOException {
		ExportDataDirectory exportDataDirectory =
			(ExportDataDirectory) reader.getFactory().create(ExportDataDirectory.class);
		exportDataDirectory.initExportDataDirectory(ntHeader, reader);
		return exportDataDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ExportDataDirectory() {
	}

	private void initExportDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
			throws IOException {
		processDataDirectory(ntHeader, reader);

		if (exports == null) {
			exports = new ExportInfo[0];
		}
	}

	/**
	 * Returns an array of the exports defined in this export data directory.
	 * @return an array of the exports defined in this export data directory
	 */
	public ExportInfo[] getExports() {
		return exports;
	}

	public int getAddressOfFunctions() {
		return addressOfFunctions;
	}

	public int getAddressOfNames() {
		return addressOfNames;
	}

	public int getAddressOfNameOrdinals() {
		return addressOfNameOrdinals;
	}

	public int getNumberOfFunctions() {
		return numberOfFunctions;
	}

	public int getNumberOfNames() {
		return numberOfNames;
	}

	public int getName() {
		return name;
	}

	public int getBase() {
		return base;
	}

	public int getCharacteristics() {
		return characteristics;
	}

	public int getTimeDateStamp() {
		return timeDateStamp;
	}

	public short getMajorVersion() {
		return majorVersion;
	}

	public short getMinorVersion() {
		return minorVersion;
	}

	public String getExportName() {
		return exportName;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {
		monitor.setMessage("[" + program.getName() + "]: exports...");

		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		ReferenceManager referenceManager = program.getReferenceManager();

		//apply the export directory data structure
		PeUtils.createData(program, addr, toDataType(), log);

		//apply string datatype on export name
		int ptrToName = getName();
		if (ptrToName > 0) {
			Address strAddr = space.getAddress(va(ptrToName, isBinary));
			createTerminatedString(program, strAddr, false, log);
			setPlateComment(program, strAddr, "Export Library Name");
		}

		long funcAddr = va(getAddressOfFunctions(), isBinary);
		long nameAddr = va(getAddressOfNames(), isBinary);
		long ordinalAddr = va(getAddressOfNameOrdinals(), isBinary);

		for (int i = 0; i < getNumberOfFunctions(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			Address address = space.getAddress(funcAddr);
			if (i == 0) {
				setPlateComment(program, address, "Export Function Pointers");
			}
			PeUtils.createData(program, address, new DWordDataType(), log);
			Data data = program.getListing().getDataAt(address);
			if (data == null || !(data.getValue() instanceof Scalar)) {
				Msg.warn(this, "Invalid or missing function at " + address);
				break;
			}
			Scalar scalar = (Scalar) data.getValue();
			Address refAddr = space.getAddress(va(scalar.getUnsignedValue(), isBinary));
			data.addOperandReference(0, refAddr, RefType.DATA, SourceType.IMPORTED);
			Reference[] refs = data.getOperandReferences(0);
			for (Reference ref : refs) {
				referenceManager.setPrimary(ref, false);
			}
			funcAddr += 4;
		}
		for (int i = 0; i < getNumberOfNames(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			Address address = space.getAddress(ordinalAddr);
			if (i == 0) {
				setPlateComment(program, address, "Export Ordinal Values");
			}
			PeUtils.createData(program, address, new WordDataType(), log);
			ordinalAddr += 2;
		}
		for (int i = 0; i < getNumberOfNames(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			Address address = space.getAddress(nameAddr);
			if (i == 0) {
				setPlateComment(program, address, "Export Name Pointers");
			}
			PeUtils.createData(program, address, new DWordDataType(), log);
			Data data = program.getListing().getDataAt(address);
			if (data == null) {
				Msg.warn(this, "Invalid or missing data at " + address);
				break;
			}
			Scalar scalar = (Scalar) data.getValue();
			Address strAddr = space.getAddress(va(scalar.getUnsignedValue(), isBinary));
			data.addOperandReference(0, strAddr, RefType.DATA, SourceType.IMPORTED);
			Reference[] refs = data.getOperandReferences(0);
			for (Reference ref : refs) {
				referenceManager.setPrimary(ref, false);
			}
			createTerminatedString(program, strAddr, true, log);
			nameAddr += 4;
		}
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public boolean parse() throws IOException {
		long oldIndex = reader.getPointerIndex();
		try {
			int ptr = getPointer();
			if (ptr < 0) {
				return false;
			}
			reader.setPointerIndex(ptr);

			characteristics = reader.readNextInt();
			timeDateStamp = reader.readNextInt();
			majorVersion = reader.readNextShort();
			minorVersion = reader.readNextShort();
			name = reader.readNextInt();
			ptr = ntHeader.rvaToPointer(name);
			if (name > 0 && ptr < 0) {
				Msg.error(this, "Invalid RVA " + Integer.toHexString(name));
				return false;
			}
			base = reader.readNextInt();
			numberOfFunctions = reader.readNextInt();
			numberOfNames = reader.readNextInt();
			addressOfFunctions = reader.readNextInt();
			addressOfNames = reader.readNextInt();
			addressOfNameOrdinals = reader.readNextInt();

			exportsStartRVA = getVirtualAddress();
			exportsEndRVA = exportsStartRVA + getSize();

			exportName = (ptr > 0) ? reader.readAsciiString(ptr) : "";

			// convert RVA's into pointers
			int pointerToFunctions = ntHeader.rvaToPointer(addressOfFunctions);
			if (numberOfFunctions > 0 && pointerToFunctions < 0) {
				Msg.error(this, "Invalid RVA " + Integer.toHexString(addressOfFunctions));
				numberOfFunctions = 0;
			}
			if (numberOfFunctions > NTHeader.MAX_SANE_COUNT) {
				Msg.error(this,
					"Large number of functions " + Integer.toHexString(numberOfFunctions));
				numberOfFunctions = 0;
			}
			int pointerToNames = ntHeader.rvaToPointer(addressOfNames);
			if (numberOfNames > 0 && pointerToNames < 0) {
				Msg.error(this, "Invalid RVA " + Integer.toHexString(addressOfNames));
				numberOfNames = 0;
			}
			int pointerToOrdinals = ntHeader.rvaToPointer(addressOfNameOrdinals);
			if (numberOfNames > 0 && pointerToOrdinals < 0) {
				Msg.error(this, "Invalid RVA " + Integer.toHexString(addressOfNameOrdinals));
				numberOfNames = 0;
			}
			if (numberOfNames > NTHeader.MAX_SANE_COUNT) {
				Msg.error(this, "Large number of names " + Integer.toHexString(numberOfNames));
				numberOfNames = 0;
			}

			List<ExportInfo> exportList = new ArrayList<>();

			for (int i = 0; i < numberOfFunctions; ++i) {
				int entryPointRVA = reader.readInt(pointerToFunctions);
				pointerToFunctions += 4;

				// Skip over gaps in exported function
				// ordinals (the entrypoint is 0 for
				// these functions).
				if (entryPointRVA == 0) {
					continue;
				}

				long addr =
					Conv.intToLong(entryPointRVA) + ntHeader.getOptionalHeader().getImageBase();

				if (!ntHeader.getOptionalHeader().is64bit()) {
					addr &= 0xffffffffL;
				}

				String lname = "";

				// See if this function has an associated name exported for it.
				for (int j = 0; j < numberOfNames; ++j) {
					int jthOrdinalVal = reader.readShort(pointerToOrdinals + (j * 2));
					if (jthOrdinalVal == i) {
						int jthNameRVA = reader.readInt(pointerToNames + (j * 4));
						int jthNamePtr = ntHeader.rvaToPointer(jthNameRVA);
						if (jthNamePtr < 0) {
							Msg.error(this, "Invalid RVA " + Integer.toHexString(jthNameRVA));
							return false;
						}
						// locate corresponding name
						lname = reader.readAsciiString(jthNamePtr);
						break;
					}
				}

				String cmt = "0x" + Integer.toHexString(entryPointRVA) + "  " +
					Integer.toString(i + base) + "  " + lname;

				boolean forwarded = false;

				if (entryPointRVA >= exportsStartRVA && entryPointRVA < exportsEndRVA) {
					int entryPointPtr = ntHeader.rvaToPointer(entryPointRVA);
					if (entryPointPtr < 0) {
						Msg.error(this, "Invalid RVA " + Integer.toHexString(entryPointRVA));
						return false;
					}
					String forwarder = reader.readAsciiString(entryPointPtr);

					cmt += "  ";
					cmt += "(forwarder -> " + forwarder + ")";

					forwarded = true;
				}

				exportList.add(new ExportInfo(addr, i + base, lname, cmt, forwarded));
			}

			exports = new ExportInfo[exportList.size()];
			exportList.toArray(exports);
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
		return true;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();
		buff.append("\t\t" + "Export Directory: [" + super.toString() + "]" + "\n");
		for (ExportInfo info : exports) {
			buff.append("\t\t\t" + "0x" + Long.toHexString(info.getAddress()) + "  " +
				info.getOrdinal() + "  " + info.getName() + "\n");
		}
		return buff.toString();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(new DWordDataType(), "Characteristics", null);
		struct.add(new DWordDataType(), "TimeDateStamp", null);
		struct.add(new WordDataType(), "MajorVersion", null);
		struct.add(new WordDataType(), "MinorVersion", null);
		struct.add(new DWordDataType(), "Name", null);
		struct.add(new DWordDataType(), "Base", null);
		struct.add(new DWordDataType(), "NumberOfFunctions", null);
		struct.add(new DWordDataType(), "NumberOfNames", null);
		struct.add(new DWordDataType(), "AddressOfFunctions", null);
		struct.add(new DWordDataType(), "AddressOfNames", null);
		struct.add(new DWordDataType(), "AddressOfNameOrdinals", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
