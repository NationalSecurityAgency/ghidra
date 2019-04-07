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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;

/**
 * Describes the PropertyMap class. Each row points to a list of properties in the Property table owned by a class.
 */
public class CliTablePropertyMap extends CliAbstractTable {
	public class CliPropertyMapRow extends CliAbstractTableRow {
		public int parentIndex;
		public int propertyListIndex;
		
		public CliPropertyMapRow(int parentIndex, int propertyListIndex) {
			super();
			this.parentIndex = parentIndex;
			this.propertyListIndex = propertyListIndex;
		}

		@Override
		public String getRepresentation() {
			// TODO: plist index points to contiguous run of properties
			return String.format("Parent %s Properties %x", getRowRepresentationSafe(CliTypeTable.TypeDef, parentIndex), propertyListIndex);
		}
	}
	
	public CliTablePropertyMap(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliPropertyMapRow(readTableIndex(reader, CliTypeTable.TypeDef), readTableIndex(reader, CliTypeTable.Property)));
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "PropertyMap Row", 0);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "Parent", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Property), "options", "Index into Property table. Points to contiguous run of Properties until next ref from PropertyMap or end of table.");
		return rowDt;
	}
}
