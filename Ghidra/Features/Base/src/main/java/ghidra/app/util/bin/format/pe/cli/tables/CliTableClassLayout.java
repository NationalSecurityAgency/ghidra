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
 * Describes the ClassLayout table. Each row has information that's useful when handing something from managed to unmanaged code.
 */
public class CliTableClassLayout extends CliAbstractTable {
	public class CliClassLayoutRow extends CliAbstractTableRow {
		public short packingSize;
		public int classSize;
		public int parentIndex;
		
		public CliClassLayoutRow(short packingSize, int classSize, int parentIndex) {
			super();
			this.packingSize = packingSize;
			this.classSize = classSize;
			this.parentIndex = parentIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("Packing %d ClassSize %d Parent %s", packingSize, classSize,
				getRowRepresentationSafe(CliTypeTable.TypeDef, parentIndex));
		}
	}
	
	public CliTableClassLayout(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliClassLayoutRow(reader.readNextShort(), reader.readNextInt(), readTableIndex(reader, CliTypeTable.TypeDef)));
		}
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "ClassLayout Row", 0);
		rowDt.add( WORD, "PackingSize", null);
		rowDt.add(DWORD, "ClassSize", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "Parent", null);
		return rowDt;
	}

}
