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
 * Describes the Module Table, which contains information about the current assembly.
 */
public class CliTableModule extends CliAbstractTable {
	public class CliModuleRow extends CliAbstractTableRow {
		public short generation;
		public int nameIndex;
		public int mvIdIndex;
		public int encIdIndex;
		public int encBaseIdIndex;
		
		public CliModuleRow(short generation, int nameIndex, int mvIdIndex, int encIdIndex,
				int encBaseIdIndex) {
			super();
			this.generation = generation;
			this.nameIndex = nameIndex;
			this.mvIdIndex = mvIdIndex;
			this.encIdIndex = encIdIndex;
			this.encBaseIdIndex = encBaseIdIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("%s MvID %s EncID %s EncBaseID %s",
				metadataStream.getGuidStream().getGuid(nameIndex),
				metadataStream.getGuidStream().getGuid(mvIdIndex),
				metadataStream.getGuidStream().getGuid(encIdIndex),
				metadataStream.getGuidStream().getGuid(encBaseIdIndex));
		}
		
		@Override
		public String getShortRepresentation() {
			return String.format("%s", metadataStream.getStringsStream().getString(nameIndex));
		}
	}
	
	public CliTableModule(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliModuleRow row = new CliModuleRow(reader.readNextShort(), readStringIndex(reader), readBlobIndex(reader), readBlobIndex(reader), readBlobIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), "Module Row", 0);
		struct.add( WORD, "Generation", "reserved, shall be 0");
		struct.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		struct.add(metadataStream.getGuidIndexDataType(), "MvId", "used to distinguish between versions of same module");
		struct.add(metadataStream.getGuidIndexDataType(), "EncId", "reserved, shall be 0");
		struct.add(metadataStream.getGuidIndexDataType(), "EncBaseId", "reserved, shall be 0");
		return struct;
	}
	
	@Override
	public DataType toDataType() {
		DataType rowDt = getRowDataType();
		return rowDt;
	}

	@Override
	public int getNumRows() {
		return 1;
	}
}
