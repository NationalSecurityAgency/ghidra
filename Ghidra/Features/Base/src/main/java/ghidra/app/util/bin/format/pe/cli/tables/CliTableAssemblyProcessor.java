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
 * Describes the AssemblyProcessor table. It is apparently ignored by the CLI and shouldn't be found in an assembly.
 */
public class CliTableAssemblyProcessor extends CliAbstractTable {
	public class CliAssemblyProcessorRow extends CliAbstractTableRow {
		public int processor;
		
		public CliAssemblyProcessorRow(int processor) {
			this.processor = processor;
		}
		
		@Override
		public String getRepresentation() {
			return String.format("Processor %d", processor);
		}
	}
	public CliTableAssemblyProcessor(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliAssemblyProcessorRow(reader.readNextInt()));
		}
	}

	@Override
	public DataType getRowDataType() {
		return toDataType();
	}
	
	@Override
	public DataType toDataType() {
		Structure rowDt = new StructureDataType(new CategoryPath(PATH), "AssemblyProcessor Row", 0);
		rowDt.add(DWORD, "Processor", null);
		return new ArrayDataType(rowDt, this.numRows, rowDt.getLength());
	}

}
