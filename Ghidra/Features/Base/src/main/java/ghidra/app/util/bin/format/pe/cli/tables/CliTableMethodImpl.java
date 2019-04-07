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
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexMethodDefOrRef;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the MethodImpl table.
 */
public class CliTableMethodImpl extends CliAbstractTable {
	public class CliMethodImplRow extends CliAbstractTableRow {
		public int classIndex;
		public int methodBodyIndex;
		public int methodDeclarationIndex;
		
		public CliMethodImplRow(int classIndex, int methodBodyIndex, int methodDeclarationIndex) {
			super();
			this.classIndex = classIndex;
			this.methodBodyIndex = methodBodyIndex;
			this.methodDeclarationIndex = methodDeclarationIndex;
		}

		@Override
		public String getRepresentation() {
			String methodBodyRep;
			try {
				methodBodyRep = getRowRepresentationSafe(CliIndexMethodDefOrRef.getTableName(methodBodyIndex), CliIndexMethodDefOrRef.getRowIndex(methodBodyIndex));
			}
			catch (InvalidInputException e) {
				methodBodyRep = Integer.toHexString(methodBodyIndex);
			}
			String methodDeclarationRep;
			try {
				methodDeclarationRep = getRowRepresentationSafe(CliIndexMethodDefOrRef.getTableName(methodDeclarationIndex), CliIndexMethodDefOrRef.getRowIndex(methodDeclarationIndex));
			}
			catch (InvalidInputException e) {
				methodDeclarationRep = Integer.toHexString(methodDeclarationIndex);
			}
			return String.format("Class %s MethodBody %s MethodDeclaration %s", getRowRepresentationSafe(CliTypeTable.TypeDef, classIndex), methodBodyRep, methodDeclarationRep);
		}
	}
	
	public CliTableMethodImpl(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliMethodImplRow(readTableIndex(reader, CliTypeTable.TypeDef), CliIndexMethodDefOrRef.readCodedIndex(reader, stream), CliIndexMethodDefOrRef.readCodedIndex(reader, stream)));
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "MethodImpl Row", 0);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "Class", "index into TypeDef");
		rowDt.add(CliIndexMethodDefOrRef.toDataType(metadataStream), "MethodBody", "MethodDefOrRef coded index");
		rowDt.add(CliIndexMethodDefOrRef.toDataType(metadataStream), "MethodDeclaration", "MethodDefOrRef coded index");
		return rowDt;
	}

}
