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
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumGenericParamAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexTypeOrMethodDef;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the GenericParam table.
 */
public class CliTableGenericParam extends CliAbstractTable {
	public class CliGenericParamRow extends CliAbstractTableRow {
		public short number;
		public short flags;
		public int ownerIndex;
		public int nameIndex;
		
		public CliGenericParamRow(short number, short flags, int ownerIndex, int nameIndex) {
			super();
			this.number = number;
			this.flags = flags;
			this.ownerIndex = ownerIndex;
			this.nameIndex = nameIndex;
		}

		@Override
		public String getRepresentation() {
			String ownerRep;
			try {
				ownerRep = getRowRepresentationSafe(CliIndexTypeOrMethodDef.getTableName(ownerIndex), CliIndexTypeOrMethodDef.getRowIndex(ownerIndex));
			}
			catch (InvalidInputException e) {
				ownerRep = Integer.toHexString(ownerIndex);
			}
			return String.format("%s Owner %s Number %d Flags %s",
				metadataStream.getStringsStream().getString(nameIndex),
				ownerRep, number,
				CliEnumGenericParamAttributes.dataType.getName(flags & 0xffff));
		}
	}
	
	public CliTableGenericParam(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliGenericParamRow row = new CliGenericParamRow(reader.readNextShort(), reader.readNextShort(), 
				CliIndexTypeOrMethodDef.readCodedIndex(reader, stream), readStringIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "GenericParam Row", 0);
		rowDt.add( WORD, "Number", "index of the generic param, numbered left-to-right, from 0");
		rowDt.add(CliEnumGenericParamAttributes.dataType, "Flags", "Bitmask of type GenericParamAttributes");
		rowDt.add(CliIndexTypeOrMethodDef.toDataType(metadataStream), "Owner", "TypeOrMethodDef coded index");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap, for description only");
		return rowDt;
	}

}
