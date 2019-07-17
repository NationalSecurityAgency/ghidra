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
 * Describes the ModuleRef table. Each row is a reference to an external module.
 */
public class CliTableModuleRef extends CliAbstractTable {
	public class CliModuleRefRow extends CliAbstractTableRow {
		public int nameIndex;
		
		public CliModuleRefRow(int nameIndex) {
			this.nameIndex = nameIndex;
		}
		
		@Override
		public String getRepresentation() {
			return String.format("ModuleRef %s", metadataStream.getStringsStream().getString(nameIndex));
		}
	}
	
	public CliTableModuleRef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliModuleRefRow row = new CliModuleRefRow(readStringIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "ModuleRef Row", 0);
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		return rowDt;
	}

}
