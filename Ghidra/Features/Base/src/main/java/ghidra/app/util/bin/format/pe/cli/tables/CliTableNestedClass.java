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
 * Describes the NestedClass table. Each row is a nested class.
 */
public class CliTableNestedClass extends CliAbstractTable {
	public class CliNestedClassRow extends CliAbstractTableRow {
		public int nestedClassIndex;
		public int enclosingClassIndex;
		
		public CliNestedClassRow(int nestedClassIndex, int enclosingClassIndex) {
			super();
			this.nestedClassIndex = nestedClassIndex;
			this.enclosingClassIndex = enclosingClassIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("%s is nested in %s", getRowRepresentationSafe(CliTypeTable.TypeDef, nestedClassIndex), getRowRepresentationSafe(CliTypeTable.TypeDef, enclosingClassIndex));
		}
	}
	
	public CliTableNestedClass(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliNestedClassRow(readTableIndex(reader, CliTypeTable.TypeDef), readTableIndex(reader, CliTypeTable.TypeDef)));
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "NestedClass Row", 0);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "NestedClass", "TypeDef index");
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "EnclosingClass", "TypeDef index");
		return rowDt;
	}
}
