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
package ghidra.app.util.bin.format.pe.cli.tables;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumPInvokeAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexMemberForwarded;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the ImplMap table.
 */
public class CliTableImplMap extends CliAbstractTable {
	public class CliImplMapRow extends CliAbstractTableRow {
		public short mappingFlags;
		public int memberForwardedIndex;
		public int importNameIndex;
		public int importScopeIndex;
		
		public CliImplMapRow(short mappingFlags, int memberForwardedIndex, int importNameIndex,
				int importScopeIndex) {
			super();
			this.mappingFlags = mappingFlags;
			this.memberForwardedIndex = memberForwardedIndex;
			this.importNameIndex = importNameIndex;
			this.importScopeIndex = importScopeIndex;
		}

		@Override
		public String getRepresentation() {
			String memberRep;
			try {
				memberRep = getRowRepresentationSafe(CliIndexMemberForwarded.getTableName(memberForwardedIndex), CliIndexMemberForwarded.getRowIndex(memberForwardedIndex));
			}
			catch (InvalidInputException e) {
				memberRep = Integer.toHexString(memberForwardedIndex);
			}
			return String.format(
				"MemberForwarded %s Routine ImportName %s Unmanaged ImportScope %s Flags %s",
				memberRep,
				metadataStream.getStringsStream().getString(importNameIndex),
				getRowRepresentationSafe(CliTypeTable.ModuleRef, importScopeIndex),
				CliEnumPInvokeAttributes.dataType.getName(mappingFlags & 0xffff));
		}
	}
	
	public CliTableImplMap(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliImplMapRow row = new CliImplMapRow(reader.readNextShort(), CliIndexMemberForwarded.readCodedIndex(reader, stream),
				readStringIndex(reader), readTableIndex(reader, CliTypeTable.ModuleRef));
			rows.add(row);
			strings.add(row.importNameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "ImplMap Row", 0);
		rowDt.add(CliEnumPInvokeAttributes.dataType, "MappingFlags", "Bitmask of type PInvokeAttributes");
		rowDt.add(CliIndexMemberForwarded.toDataType(metadataStream), "MemberForwarded", "MemberForwarded Coded Index");
		rowDt.add(metadataStream.getStringIndexDataType(), "ImportName", "index into String heap");
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.ModuleRef), "ImportScope", "Index into ModuleRef table");
		return rowDt;
	}

}
