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
 * Describes the AssemblyRefOS table. Apparently it is ignored by the CLI and shouldn't be found in an assembly.
 */
public class CliTableAssemblyRefOS extends CliAbstractTable {
	public class CliAssemblyRefOSRow extends CliAbstractTableRow {
		public int osPlatformID;
		public int osMajorVersion;
		public int osMinorVersion;
		public int assemblyRefIndex;
		
		public CliAssemblyRefOSRow(int osPlatformID, int osMajorVersion, int osMinorVersion, int assemblyRefIndex) {
			super();
			this.osPlatformID = osPlatformID;
			this.osMajorVersion = osMajorVersion;
			this.osMinorVersion = osMinorVersion;
			this.assemblyRefIndex = assemblyRefIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("%d v%d.%d", osPlatformID, osMajorVersion, osMinorVersion);
		}
	}
	
	public CliTableAssemblyRefOS(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliAssemblyRefOSRow(reader.readNextInt(), reader.readNextInt(), reader.readNextInt(), readTableIndex(reader, CliTypeTable.AssemblyRef)));
		}
	}
	
	@Override
	public DataType getRowDataType() {
		return toDataType();
	}

	@Override
	public DataType toDataType() {
		Structure rowDt = new StructureDataType(new CategoryPath(PATH), "AssemblyRefOS Row", 0);
		rowDt.add(DWORD, "OSPlatformID", null);
		rowDt.add(DWORD, "OSMajorVersion", null);
		rowDt.add(DWORD, "OSMinorVersion", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.AssemblyRef), "AssemblyRef", "index into AssemblyRef table");
		return new ArrayDataType(rowDt, this.numRows, rowDt.getLength());
	}

}
