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
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexTypeDefOrRef;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the TypeDef table. Each row represents a class in the current assembly.
 */
public class CliTableTypeDef extends CliAbstractTable {
	public class CliTypeDefRow extends CliAbstractTableRow {
		public int flags;
		public int typeNameIndex;
		public int typeNamespaceIndex;
		public int extendsIndex;
		public int fieldListIndex;
		public int methodListIndex;
		
		public CliTypeDefRow(int flags, int typeNameIndex, int typeNamespaceIndex,
				int extendsIndex, int fieldListIndex, int methodListIndex) {
			super();
			this.flags = flags;
			this.typeNameIndex = typeNameIndex;
			this.typeNamespaceIndex = typeNamespaceIndex;
			this.extendsIndex = extendsIndex;
			this.fieldListIndex = fieldListIndex;
			this.methodListIndex = methodListIndex;
		}

		@Override
		public String getShortRepresentation() {
			return String.format("%s.%s",
				metadataStream.getStringsStream().getString(typeNamespaceIndex),
				metadataStream.getStringsStream().getString(typeNameIndex));
		}
		
		@Override
		public String getRepresentation() {
			String extendsRep;
			if (extendsIndex == 0) {
				extendsRep = "Nothing";
			}
			else {
				try {
					extendsRep = getRowRepresentationSafe(CliIndexTypeDefOrRef.getTableName(extendsIndex), CliIndexTypeDefOrRef.getRowIndex(extendsIndex));
				}
				catch (InvalidInputException e) {
					extendsRep = Integer.toHexString(extendsIndex);
				}
			}
			// TODO: FieldList and MethodList point to contiguous runs of fields and methods, not just singles
			return String.format("Type %s Namespace %s Extends %s Fields %s MethodList %s Flags %s",
				metadataStream.getStringsStream().getString(typeNameIndex),
				metadataStream.getStringsStream().getString(typeNamespaceIndex),
				extendsRep, getRowRepresentationSafe(CliTypeTable.Field, fieldListIndex),
				getRowRepresentationSafe(CliTypeTable.MethodDef, methodListIndex), CliEnumTypeAttributes.dataType.getName(flags & 0xffffffff));
		}
	}
	
	public CliTableTypeDef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliTypeDefRow row = new CliTypeDefRow(reader.readNextInt(), readStringIndex(reader), readStringIndex(reader), CliIndexTypeDefOrRef.readCodedIndex(reader, stream),
				readTableIndex(reader, CliTypeTable.Field), readTableIndex(reader, CliTypeTable.MethodDef));
			rows.add(row);
			strings.add(row.typeNameIndex);
			strings.add(row.typeNamespaceIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	public int getOwnerOfFieldIndex(int fieldIndex) {
		for (int i = 0; i < this.numRows; i++) {
			CliTypeDefRow row = (CliTypeDefRow) rows.get(i);
			if (i == this.numRows - 1) {
				if (fieldIndex >= row.fieldListIndex)
					return i + 1;
				return -1;
			}
			CliTypeDefRow nextRow = (CliTypeDefRow) rows.get(i+1);
			if (fieldIndex >= row.fieldListIndex && fieldIndex < nextRow.fieldListIndex)
				return i + 1;
		}
		return -1;
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "TypeDef Row", 0);
		rowDt.add(CliEnumTypeAttributes.dataType, "Flags", "see CorTypeAttr");
		rowDt.add(metadataStream.getStringIndexDataType(), "TypeName", "index into String heap");
		rowDt.add(metadataStream.getStringIndexDataType(), "TypeNamespace", "index into String heap");
		rowDt.add(CliIndexTypeDefOrRef.toDataType(metadataStream), "Extends", "index: coded TypeDefOrRef");
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Field), "FieldList", "index into Field table");
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.MethodDef), "MethodList", "index into MethodDef table");
		return rowDt;
	}

}
