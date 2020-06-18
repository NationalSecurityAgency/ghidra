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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.vdex.VdexHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * https://android.googlesource.com/platform/art/+/pie-release/runtime/oat_file.h#518
 */
class OatDexFile_Pie extends OatDexFile {

	private int dex_file_location_;
	private String canonical_dex_file_location_;
	private int dex_file_location_checksum_;
	private int dex_file_pointer_;
	private int lookup_table_data_;
	private int method_bss_mapping_;
	private int type_bss_mapping_;
	private int string_bss_mapping_;
	private int oat_class_offsets_pointer_;
	private int lookup_table_;
	private int dex_layout_sections_;//according to spec this field should exist, but it does not

	private long _offset;
	private DexHeader dexHeader;

	OatDexFile_Pie(BinaryReader reader, VdexHeader vdexHeader) throws IOException {
		_offset = reader.getPointerIndex();

		dex_file_location_ = reader.readNextInt();
		canonical_dex_file_location_ = reader.readNextAsciiString(dex_file_location_);
		dex_file_location_checksum_ = reader.readNextInt();
		dex_file_pointer_ = reader.readNextInt();
		lookup_table_data_ = reader.readNextInt();
		method_bss_mapping_ = reader.readNextInt();
		type_bss_mapping_ = reader.readNextInt();
		string_bss_mapping_ = reader.readNextInt();
		oat_class_offsets_pointer_ = reader.readNextInt();
		lookup_table_ = reader.readNextInt();
		//dex_layout_sections_         = reader.readNextInt( );//according to spec this field should exist, but it does not

		if (vdexHeader != null) {
			for (int i = 0; i < vdexHeader.getDexChecksums().length; ++i) {
				if (vdexHeader.getDexChecksums()[i] == getDexFileChecksum()) {
					if (vdexHeader.getDexHeaderList().size() > i) {
						dexHeader = vdexHeader.getDexHeaderList().get(i);
						break;
					}
				}
			}
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

	@Override
	public boolean isDexHeaderExternal() {
		return true;
	}

	public int getLookupTable() {
		return lookup_table_;
	}

	public int getLookupTableData() {
		return lookup_table_data_;
	}

	public int getMethodBssMapping() {
		return method_bss_mapping_;
	}

	public int getTypeBssMapping() {
		return type_bss_mapping_;
	}

	public int getStringBssMapping() {
		return string_bss_mapping_;
	}

	public int getOatClassOffsetsPointer() {
		return oat_class_offsets_pointer_;
	}

	public int getDexLayoutSections() {
		return dex_layout_sections_;
	}

	@Override
	public void markup(OatHeader oatHeader, Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Symbol oatDataSymbol = OatUtilities.getOatDataSymbol(program);
		Address address = oatDataSymbol.getAddress();

		Address dataAddress = address.add(_offset);
		Data data = program.getListing().createData(dataAddress, toDataType());

		for (int i = 0; i < data.getNumComponents(); ++i) {
			monitor.checkCanceled();
			Data componentI = data.getComponent(i);
			if (componentI.getFieldName().startsWith("lookup_table_data_") ||
				componentI.getFieldName().startsWith("oat_class_offsets_pointer_") ||
				componentI.getFieldName().startsWith("lookup_table_data_") ||
				componentI.getFieldName().startsWith("method_bss_mapping_") ||
				componentI.getFieldName().startsWith("type_bss_mapping_") ||
				componentI.getFieldName().startsWith("string_bss_mapping_") ||
				componentI.getFieldName().startsWith("oat_class_offsets_pointer_") ||
				componentI.getFieldName().startsWith("lookup_table_") ||
				componentI.getFieldName().startsWith("dex_layout_sections_")) {

				Scalar scalar = componentI.getScalar(0);
				if (scalar.getUnsignedValue() == 0) {
					continue;
				}

				Address destinationAddress = address.add(scalar.getUnsignedValue());
				program.getReferenceManager()
						.addMemoryReference(componentI.getMinAddress(), destinationAddress,
							RefType.DATA, SourceType.ANALYSIS, 0);
				program.getSymbolTable()
						.createLabel(destinationAddress, componentI.getFieldName(),
							SourceType.ANALYSIS);

				if (componentI.getFieldName().startsWith("lookup_table_data_")) {
					OatDexFileUtilities.markupLookupTableData(this.getClass(), destinationAddress,
						dexHeader, oatHeader, program, monitor, log);
				}
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatDexFile_Pie.class);

		Structure structure = new StructureDataType(className + "_" + dex_file_location_, 0);

		structure.add(DWORD, "dex_file_location_", null);
		structure.add(STRING, dex_file_location_, "canonical_dex_file_location_", null);
		structure.add(DWORD, "dex_file_location_checksum_", null);
		structure.add(DWORD, "dex_file_pointer_", null);
		structure.add(DWORD, "lookup_table_data_", null);
		structure.add(DWORD, "method_bss_mapping_", null);
		structure.add(DWORD, "type_bss_mapping_", null);
		structure.add(DWORD, "string_bss_mapping_", null);
		structure.add(DWORD, "oat_class_offsets_pointer_", null);
		structure.add(DWORD, "lookup_table_", null);
		//structure.add( DWORD, "dex_layout_sections_", null );//according to spec this field should exist, but it does not

		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
