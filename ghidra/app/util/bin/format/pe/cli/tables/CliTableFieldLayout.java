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
 * Describes the FieldLayout table. Serves a similar purpose to ClassLayout; it's useful when passing to unmanaged code.
 */
public class CliTableFieldLayout extends CliAbstractTable {
	public class CliFieldLayoutRow extends CliAbstractTableRow {
		public int offset;
		public int fieldIndex;
		
		public CliFieldLayoutRow(int offset, int fieldIndex) {
			super();
			this.offset = offset;
			this.fieldIndex = fieldIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("Field %s Offset %d", getRowRepresentationSafe(CliTypeTable.Field, fieldIndex), offset);
		}
	}
	
	public CliTableFieldLayout(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliFieldLayoutRow(reader.readNextInt(), readTableIndex(reader, CliTypeTable.Field)));
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "FieldLayout Row", 0);
		rowDt.add(DWORD, "Offset", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Field), "Field", null);
		return rowDt;
	}
}
