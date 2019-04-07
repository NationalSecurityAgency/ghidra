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
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexHasDeclSecurity;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the DeclSecurity table. Each row attaches security attributes to a class, method, or assembly.
 */
public class CliTableDeclSecurity extends CliAbstractTable {
	public class CliDeclSecurityRow extends CliAbstractTableRow {
		public short action;
		public int parentIndex;
		public int permissionSetIndex;
		
		public CliDeclSecurityRow(short action, int parentIndex, int permissionSetIndex) {
			super();
			this.action = action;
			this.parentIndex = parentIndex;
			this.permissionSetIndex = permissionSetIndex;
		}

		@Override
		public String getRepresentation() {
			String parentRep;
			try {
				parentRep = getRowRepresentationSafe(CliIndexHasDeclSecurity.getTableName(parentIndex), CliIndexHasDeclSecurity.getRowIndex(parentIndex));
			}
			catch (InvalidInputException e) {
				parentRep = Integer.toHexString(parentIndex);
			}
			return String.format("Action %d Parent %s PermissionSet %x", action, parentRep, permissionSetIndex);
		}
	}
	
	public CliTableDeclSecurity(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliDeclSecurityRow row = new CliDeclSecurityRow(reader.readNextShort(), CliIndexHasDeclSecurity.readCodedIndex(reader, stream), readBlobIndex(reader));
			blobs.add(row.permissionSetIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "DeclSecurity Row", 0);
		rowDt.add( WORD, "Action", "Points to a System.Security.SecurityAction as described in ISO23271 IV");
		rowDt.add(CliIndexHasDeclSecurity.toDataType(metadataStream), "Parent", null);
		rowDt.add(metadataStream.getBlobIndexDataType(), "PermissionSet", null);
		return rowDt;
	}
}
