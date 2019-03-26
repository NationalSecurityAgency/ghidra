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
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodSemanticsAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexHasSemantics;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the MethodSemantics table. Each row is a link between a property or event and a specific method.
 * Events are routinely associated with more than one method, and properties use this for get/set methods.
 */
public class CliTableMethodSemantics extends CliAbstractTable {
	public class CliMethodSemanticsRow extends CliAbstractTableRow {
		public short semantics;
		public int methodIndex;
		public int associationIndex;
		
		public CliMethodSemanticsRow(short semantics, int methodIndex, int associationIndex) {
			super();
			this.semantics = semantics;
			this.methodIndex = methodIndex;
			this.associationIndex = associationIndex;
		}

		@Override
		public String getRepresentation() {
			String assocRep;
			try {
				assocRep = getRowRepresentationSafe(CliIndexHasSemantics.getTableName(associationIndex), CliIndexHasSemantics.getRowIndex(associationIndex));
			}
			catch (InvalidInputException e) {
				assocRep = Integer.toHexString(associationIndex);
			}
			return String.format("Method %s Association %s Semantics %s", getRowRepresentationSafe(CliTypeTable.MethodDef, methodIndex), assocRep, 
				CliEnumMethodSemanticsAttributes.dataType.getName(semantics & 0xffff));
		}
	}
	
	public CliTableMethodSemantics(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliMethodSemanticsRow(reader.readNextShort(), readTableIndex(reader, CliTypeTable.MethodDef), CliIndexHasSemantics.readCodedIndex(reader, stream)));
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "MethodSemantics Row", 0);
		rowDt.add(CliEnumMethodSemanticsAttributes.dataType, "Semantics", "Bitmask of type MethodSemanticsAttributes");
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.MethodDef), "Method", "index into MethodDef table");
		rowDt.add(CliIndexHasSemantics.toDataType(metadataStream), "Association", "HasSemantics coded index into Event or Property");
		return rowDt;
	}

}
