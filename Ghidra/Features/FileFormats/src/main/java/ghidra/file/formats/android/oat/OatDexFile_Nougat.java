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
package ghidra.file.formats.android.oat;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Used for OAT Header version 079 to 088.
 * 
 * Versions: Nougat, Nougat MR1
 * 
 * https://android.googlesource.com/platform/art/+/nougat-release/runtime/oat_file.h#383
 */
class OatDexFile_Nougat extends OatDexFile {

	protected int dex_file_location_;
	protected String canonical_dex_file_location_;
	protected int dex_file_location_checksum_;
	protected int dex_file_pointer_;
	protected int lookup_table_data_;
	protected int oat_class_offsets_pointer_;

	protected DexHeader dexHeader;

	OatDexFile_Nougat(BinaryReader reader) throws IOException {
		dex_file_location_ = reader.readNextInt();
		canonical_dex_file_location_ = reader.readNextAsciiString(dex_file_location_);
		dex_file_location_checksum_ = reader.readNextInt();
		dex_file_pointer_ = reader.readNextInt();
		lookup_table_data_ = reader.readNextInt();
		oat_class_offsets_pointer_ = reader.readNextInt();

		if (!isDexHeaderExternal()) {
			ByteProvider provider = reader.getByteProvider();
			ByteProvider tmpProvider = new ByteProviderWrapper(provider, dex_file_pointer_,
				provider.length() - dex_file_pointer_);
			BinaryReader tmpReader = new BinaryReader(tmpProvider, reader.isLittleEndian());
			dexHeader = DexHeaderFactory.getDexHeader(tmpReader);
		}
	}

	@Override
	public int getDexFileChecksum() {
		return dex_file_location_checksum_;
	}

	@Override
	public DexHeader getDexHeader() {
		return dexHeader;
	}

	@Override
	public int getDexFileOffset() {
		return dex_file_pointer_;
	}

	@Override
	public String getDexFileLocation() {
		return canonical_dex_file_location_;
	}

	public int getLookupTableData() {
		return lookup_table_data_;
	}

	public int getOatClassOffsetsPointer() {
		return oat_class_offsets_pointer_;
	}

	@Override
	public boolean isDexHeaderExternal() {
		return false;
	}

	@Override
	public void markup(OatHeader oatHeader, Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Symbol oatDataSymbol = OatUtilities.getOatDataSymbol(program);
		Address address = oatDataSymbol.getAddress();

		Listing listing = program.getListing();
		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();

		Data oatHeaderData = listing.getDefinedDataAt(address);
		if (oatHeaderData == null ||
			!oatHeaderData.getDataType().getName().startsWith("OatHeader")) {
			return;
		}
		for (int i = 0; i < oatHeaderData.getNumComponents(); ++i) {
			monitor.checkCanceled();
			Data componentI = oatHeaderData.getComponent(i);
			if (componentI.getFieldName().startsWith(OatDexFile.PREFIX)) {
				for (int j = 0; j < componentI.getNumComponents(); ++j) {
					monitor.checkCanceled();
					Data componentJ = componentI.getComponent(j);
					if (componentJ.getFieldName().startsWith("canonical_dex_file_location_")) {
						if (!canonical_dex_file_location_.equals(componentJ.getValue())) {
							break;//not the correct structure...
						}
					}
					if (componentJ.getFieldName().startsWith("oat_class_offsets_pointer_") ||
						componentJ.getFieldName().startsWith("lookup_table_data_") ||
						componentJ.getFieldName().startsWith("oat_class_offsets_pointer_")) {

						Scalar scalar = componentJ.getScalar(0);
						Address destinationAddress = address.add(scalar.getUnsignedValue());
						referenceManager.addMemoryReference(componentJ.getMinAddress(),
							destinationAddress, RefType.DATA, SourceType.ANALYSIS, 0);
						symbolTable.createLabel(destinationAddress, componentJ.getFieldName(),
							SourceType.ANALYSIS);

						if (componentJ.getFieldName().startsWith("lookup_table_data_")) {
							OatDexFileUtilities.markupLookupTableData(this.getClass(),
								destinationAddress, dexHeader, oatHeader, program, monitor, log);
						}
						if (componentJ.getFieldName().startsWith("oat_class_offsets_pointer_")) {
							OatDexFileUtilities.markupOatClassOffsetsPointer(this.getClass(),
								destinationAddress, dexHeader, oatHeader, program, monitor, log);
						}
					}
				}
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatDexFile_Nougat.class);
		Structure structure =
			new StructureDataType(className + "_" + Integer.toHexString(dex_file_location_), 0);
		structure.add(DWORD, "dex_file_location_", null);
		structure.add(STRING, dex_file_location_, "canonical_dex_file_location_", null);
		structure.add(DWORD, "dex_file_location_checksum_", null);
		structure.add(DWORD, "dex_file_pointer_", null);
		structure.add(DWORD, "lookup_table_data_", null);
		structure.add(DWORD, "oat_class_offsets_pointer_", null);

		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
