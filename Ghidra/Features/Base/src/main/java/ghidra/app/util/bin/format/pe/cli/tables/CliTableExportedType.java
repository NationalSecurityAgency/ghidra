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
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumTypeAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexHasConstant;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexImplementation;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the ExportedType table.
 */
public class CliTableExportedType extends CliAbstractTable {
	public class CliExportedTypeRow extends CliAbstractTableRow {
		public int flags;
		public int typeDefIdIndex;
		public int typeNameIndex;
		public int typeNamespaceIndex;
		public int implementationIndex;
		
		public CliExportedTypeRow(int flags, int typeDefIdIndex, int typeNameIndex,
				int typeNamespaceIndex, int implementationIndex) {
			super();
			this.flags = flags;
			this.typeDefIdIndex = typeDefIdIndex;
			this.typeNameIndex = typeNameIndex;
			this.typeNamespaceIndex = typeNamespaceIndex;
			this.implementationIndex = implementationIndex;
		}

		@Override
		public String getRepresentation() {
			String implRep;
			try {
				implRep = getRowRepresentationSafe(CliIndexImplementation.getTableName(implementationIndex), CliIndexHasConstant.getRowIndex(implementationIndex));
			}
			catch (InvalidInputException e) {
				implRep = Integer.toHexString(implementationIndex);
			}
			return String.format("%s Namespace %s Flags %s TypeDef %s Implementation %s",
				metadataStream.getStringsStream().getString(typeNameIndex),
				metadataStream.getStringsStream().getString(typeNamespaceIndex),
				CliEnumTypeAttributes.dataType.getName(flags & 0xffffffff), "", implRep);
				// TODO: getRowFromTable(TableName.TypeDef, typeDefIdIndex) instead of "", need to verify the meaning of the field. can there be multiple modules per assembly?
		}
	}
	
	public CliTableExportedType(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliExportedTypeRow row = new CliExportedTypeRow(reader.readNextInt(), reader.readNextInt(), readStringIndex(reader), readStringIndex(reader),
				CliIndexImplementation.readCodedIndex(reader, stream));
			rows.add(row);
			strings.add(row.typeNameIndex);
			strings.add(row.typeNamespaceIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "ExportedType Row", 0);
		rowDt.add(CliEnumTypeAttributes.dataType, "Flags", "Bitmask of type TypeAttributes");
		rowDt.add(DWORD, "TypeDefId", "4B index into TypeDef table of another module in this Assembly. Hint only. Must match other fields in this row.");
		rowDt.add(metadataStream.getStringIndexDataType(), "TypeName", "index into String heap");
		rowDt.add(metadataStream.getStringIndexDataType(), "TypeNamespace", "index into String heap");
		rowDt.add(CliIndexImplementation.toDataType(metadataStream), "Implementation", "index into File or ExportedType table.");
		return rowDt;
	}

}
