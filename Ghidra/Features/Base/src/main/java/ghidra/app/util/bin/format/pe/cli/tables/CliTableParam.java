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
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumParamAttributes;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;

/**
 * Describes the Param table. Each row represents a method's parameter.
 */
public class CliTableParam extends CliAbstractTable {
	public class CliParamRow extends CliAbstractTableRow {
		public short flags;
		public short sequence;
		public int nameIndex;

		private static final int PARAMATTRIBUTES_IN = 0x1;
		private static final int PARAMATTRIBUTES_OUT = 0x2;
		private static final int PARAMATTRIBUTES_OPTIONAL = 0x10;
		private static final int PARAMATTRIBUTES_HASDEFAULT = 0x1000;
		private static final int PARAMATTRIBUTES_HASFIELDMARSHAL = 0x2000;
		private static final int PARAMATTRIBUTES_UNUSED = 0xCFE0;

		public CliParamRow(short flags, short sequence, int nameIndex) {
			super();
			this.flags = flags;
			this.sequence = sequence;
			this.nameIndex = nameIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("%s Flags %s Sequence %x",
				metadataStream.getStringsStream().getString(nameIndex),
				CliEnumParamAttributes.dataType.getName(flags & 0xffff), sequence);
		}
	}

	public CliTableParam(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliParamRow row = new CliParamRow(reader.readNextShort(), reader.readNextShort(),
				readStringIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "ParamRow", 0);
		rowDt.add(CliEnumParamAttributes.dataType, "Flags", "bitmask of type ParamAttributes");
		rowDt.add(WORD, "Sequence", "constant");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		return rowDt;
	}

}
