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
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexResolutionScope;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the TypeRef table. Each row represents an imported class, its namespace, and the assembly which contains it.
 */
public class CliTableTypeRef extends CliAbstractTable {
	public class CliTypeRefRow extends CliAbstractTableRow {
		public int resolutionScopeIndex;
		public int typeNameIndex;
		public int typeNamespaceIndex;
		
		public CliTypeRefRow(int resolutionScopeIndex, int typeNameIndex, int typeNamespaceIndex) {
			super();
			this.resolutionScopeIndex = resolutionScopeIndex;
			this.typeNameIndex = typeNameIndex;
			this.typeNamespaceIndex = typeNamespaceIndex;
		}

		@Override
		public String getRepresentation() {
			String scopeRep;
			try {
				scopeRep = getRowShortRepSafe(CliIndexResolutionScope.getTableName(resolutionScopeIndex), CliIndexResolutionScope.getRowIndex(resolutionScopeIndex));
			}
			catch (InvalidInputException e) {
				scopeRep = Integer.toHexString(resolutionScopeIndex);
			}
			return String.format("%s.%s (ResolutionScope %s)",
				metadataStream.getStringsStream().getString(typeNameIndex),
				metadataStream.getStringsStream().getString(typeNamespaceIndex),
				scopeRep);
		}
		
		@Override
		public String getShortRepresentation() {
			return String.format("%s.%s",
				metadataStream.getStringsStream().getString(typeNamespaceIndex),
				metadataStream.getStringsStream().getString(typeNameIndex));
		}
		
	}
	
	public CliTableTypeRef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliTypeRefRow row = new CliTypeRefRow(CliIndexResolutionScope.readCodedIndex(reader, stream), readStringIndex(reader), readStringIndex(reader));
			rows.add(row);
			strings.add(row.typeNameIndex);
			strings.add(row.typeNamespaceIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "TypeRef Row", 0);
		rowDt.add(CliIndexResolutionScope.toDataType(metadataStream), "ResolutionScope", null);
		rowDt.add(metadataStream.getStringIndexDataType(), "TypeName", null);
		rowDt.add(metadataStream.getStringIndexDataType(), "TypeNamespace", null);
		return rowDt;
	}
}
