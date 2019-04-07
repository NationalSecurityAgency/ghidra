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
 * Describes the GenericParamConstraint table.
 */
public class CliTableGenericParamConstraint extends CliAbstractTable {
	public class CliGenericParamConstraintRow extends CliAbstractTableRow {
		public int ownerIndex;
		public int constraintIndex;
		
		public CliGenericParamConstraintRow(int ownerIndex, int constraintIndex) {
			super();
			this.ownerIndex = ownerIndex;
			this.constraintIndex = constraintIndex;
		}

		@Override
		public String getRepresentation() {
			String constraintRep;
			try {
				constraintRep = getRowRepresentationSafe(CliIndexTypeDefOrRef.getTableName(constraintIndex), CliIndexTypeDefOrRef.getRowIndex(constraintIndex));
			}
			catch (InvalidInputException e) {
				constraintRep = Integer.toHexString(constraintIndex);
			}
			return String.format("Constraint %s Owner %s", constraintRep, getRowRepresentationSafe(CliTypeTable.GenericParam, ownerIndex));
		}
	}
	
	public CliTableGenericParamConstraint(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliGenericParamConstraintRow(readTableIndex(reader, CliTypeTable.GenericParam), CliIndexTypeDefOrRef.readCodedIndex(reader, stream)));
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "GenericParamConstraint Row", 0);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.GenericParam), "Owner", "index into GenericParam table");
		rowDt.add(CliIndexTypeDefOrRef.toDataType(metadataStream), "Constraint", "class/interface this param is constrained to derive/implement");
		return rowDt;
	}

}
