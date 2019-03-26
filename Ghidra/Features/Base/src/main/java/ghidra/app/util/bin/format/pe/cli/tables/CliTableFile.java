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
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumFileAttributes;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;

/**
 * Describes the File table. Each row is a reference to an external file.
 */
public class CliTableFile extends CliAbstractTable {
	public class CliFileRow extends CliAbstractTableRow {
		public int flags;
		public int nameIndex;
		public int hashIndex;
		
		public CliFileRow(int flags, int nameIndex, int hashIndex) {
			super();
			this.flags = flags;
			this.nameIndex = nameIndex;
			this.hashIndex = hashIndex;
		}

		@Override
		public String getRepresentation() {
			String hashRep = "Index " + Integer.toHexString(hashIndex); // TODO: Make this reflect the blob contents (encoded hash? byte array?)
			return String.format("%s Hash %s Flags %s",
				metadataStream.getStringsStream().getString(nameIndex), hashRep,
				CliEnumFileAttributes.dataType.getName(flags & 0xffffffff));
		}
	}
	
	public CliTableFile(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliFileRow row = new CliFileRow(reader.readNextInt(), readStringIndex(reader), readBlobIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
			blobs.add(row.hashIndex);
		}
		reader.setPointerIndex(this.readerOffset);

	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "File Row", 0);
		rowDt.add(CliEnumFileAttributes.dataType, "Flags", "Bitmask of type FileAttributes");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		rowDt.add(metadataStream.getBlobIndexDataType(), "Hash", "index into Blob heap");
		return rowDt;
	}
	
}
