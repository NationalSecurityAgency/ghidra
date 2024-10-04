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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of Function ID type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class FunctionIdMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1601;

	private RecordNumber scopeIdRecordNumber; // zero if global
	private RecordNumber functionTypeRecordNumber;
	private String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public FunctionIdMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		scopeIdRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.ITEM, 32);
		functionTypeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		name = reader.parseString(pdb, StringParseType.StringNt);
		reader.skipPadding();
	}

	@Override
	public String getName() {
		return name;
	}

	public RecordNumber getScopeIdRecordNumber() {
		return scopeIdRecordNumber;
	}

	public RecordNumber getFunctionTypeRecordNumber() {
		return functionTypeRecordNumber;
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		// Zero if global
		if (scopeIdRecordNumber != RecordNumber.NO_TYPE) {
			myBuilder.append(pdb.getTypeRecord(scopeIdRecordNumber));
			myBuilder.append("::");
		}
		myBuilder.append(name);
		pdb.getTypeRecord(functionTypeRecordNumber).emit(myBuilder, Bind.NONE);
		builder.append("FunctionId for: ");
		builder.append(myBuilder);
	}

}
