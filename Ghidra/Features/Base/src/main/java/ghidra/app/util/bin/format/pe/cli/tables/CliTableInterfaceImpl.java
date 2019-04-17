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
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexTypeDefOrRef;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the InterfaceImpl table. Each row informs the framework of a class that implements a specific interface.
 */
public class CliTableInterfaceImpl extends CliAbstractTable {
	public class CliInterfaceImplRow extends CliAbstractTableRow {
		public int classIndex;
		public int interfaceIndex;
		
		public CliInterfaceImplRow(int classIndex, int interfaceIndex) {
			super();
			this.classIndex = classIndex;
			this.interfaceIndex = interfaceIndex;
		}

		@Override
		public String getRepresentation() {
			String interfaceRep;
			try {
				interfaceRep = getRowRepresentationSafe(CliIndexTypeDefOrRef.getTableName(interfaceIndex), CliIndexTypeDefOrRef.getRowIndex(interfaceIndex));
			}
			catch (InvalidInputException e) {
				interfaceRep = Integer.toHexString(interfaceIndex);
			}
			return String.format("Class %s implements Interface %s", getRowRepresentationSafe(CliTypeTable.TypeDef, classIndex), interfaceRep);
		}
	}

	public CliTableInterfaceImpl(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliInterfaceImplRow(readTableIndex(reader, CliTypeTable.TypeDef), CliIndexTypeDefOrRef.readCodedIndex(reader, stream)));
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "InterfaceImpl Row",0);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "Class", "index into TypeDef table");
		rowDt.add(CliIndexTypeDefOrRef.toDataType(metadataStream), "Interface", "index into TypeDef/TypeRef/TypeSpec - TypeDefOrRef coded");
		return rowDt;
	}
	
}
