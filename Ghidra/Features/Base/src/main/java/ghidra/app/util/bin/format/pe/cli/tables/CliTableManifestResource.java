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
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumManifestResourceAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexImplementation;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the ManifestResources table. Each row is a reference to an external or internal resource.
 */
public class CliTableManifestResource extends CliAbstractTable {	
	public class CliManifestResourceRow extends CliAbstractTableRow {
		public int offset;
		public int flags;
		public int nameIndex;
		public int implIndex;
		
		public CliManifestResourceRow(int offset, int flags, int nameIndex, int implIndex) {
			this.offset = offset;
			this.flags = flags;
			this.nameIndex = nameIndex;
			this.implIndex = implIndex;
		}
		
		@Override
		public String getRepresentation() {
			String implRep;
			try {
				implRep = getRowRepresentationSafe(CliIndexImplementation.getTableName(implIndex), CliIndexImplementation.getRowIndex(implIndex));
			}
			catch (InvalidInputException e) {
				implRep = Integer.toHexString(implIndex);
			}
			return String.format("%s Offset %x Flags %s Implementation %s",
				metadataStream.getStringsStream().getString(nameIndex),
				offset, CliEnumManifestResourceAttributes.dataType.getName(flags & 0xffffffff),
				implRep);
		}
	}
	
	public CliTableManifestResource(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliManifestResourceRow row = new CliManifestResourceRow(reader.readNextInt(), reader.readNextInt(), readStringIndex(reader), 
				CliIndexImplementation.readCodedIndex(reader, stream));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);

	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "ManifestResource Row", 0);
		rowDt.add(DWORD, "Offset", null);
		rowDt.add(CliEnumManifestResourceAttributes.dataType, "Flags", "Bitmask of type ManifestResourceAttributes");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		rowDt.add(CliIndexImplementation.toDataType(metadataStream), "Implementation", "Implementation coded index");
		return rowDt;
	}

}
