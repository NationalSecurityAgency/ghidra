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
 * Describes the FieldRVA table. Each row gives the RVA location of an initial value for each Field.
 */
public class CliTableFieldRVA extends CliAbstractTable {
	public class CliFieldRVARow extends CliAbstractTableRow {
		public int rva;
		public int fieldIndex;
		
		public CliFieldRVARow(int rva, int fieldIndex) {
			super();
			this.rva = rva;
			this.fieldIndex = fieldIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("Field %s RVA %x", getRowRepresentationSafe(CliTypeTable.Field, fieldIndex), rva);
		}
	}
	
	public CliTableFieldRVA(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliFieldRVARow(reader.readNextInt(), readTableIndex(reader, CliTypeTable.Field)));
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "FieldRVA Row", 0);
		rowDt.add(DWORD, "RVA", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Field), "Field", "index into Field table");
		return rowDt;
	}
}
