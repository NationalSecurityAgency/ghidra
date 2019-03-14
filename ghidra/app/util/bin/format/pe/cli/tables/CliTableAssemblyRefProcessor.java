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
import ghidra.program.model.data.*;

/**
 * Describes the AssemblyRefProcessor table. Apparently it is ignored by the CLI and shouldn't be present in an assembly.
 */
public class CliTableAssemblyRefProcessor extends CliAbstractTable {
	public class CliAssemblyRefProcessorRow extends CliAbstractTableRow {
		public int processor;
		public int assemblyRefIndex;
		
		public CliAssemblyRefProcessorRow(int processor, int assemblyRefIndex) {
			super();
			this.processor = processor;
			this.assemblyRefIndex = assemblyRefIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("Processor %d AssemblyRef: %s", processor,
				getRowRepresentationSafe(CliTypeTable.AssemblyRef, assemblyRefIndex));
		}
	}
	
	public CliTableAssemblyRefProcessor(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliAssemblyRefProcessorRow(reader.readNextInt(), readTableIndex(reader, CliTypeTable.AssemblyRef)));
		}
	}

	@Override
	public DataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "AssemblyRefProcessor Row", 0);
		rowDt.add(DWORD, "Processor", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.AssemblyRef), "AssemblyRef", "index into AssemblyRef table");
		return rowDt;
	}

}
