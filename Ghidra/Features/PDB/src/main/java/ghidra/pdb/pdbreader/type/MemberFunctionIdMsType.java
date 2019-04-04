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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

public class MemberFunctionIdMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1602;

	private AbstractTypeIndex parentTypeIndex;
	private AbstractTypeIndex functionType;
	private AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public MemberFunctionIdMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		parentTypeIndex = new TypeIndex32();
		functionType = new TypeIndex32();
		name = new StringNt();

		parentTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, parentTypeIndex.get()));
		pdb.popDependencyStack();
		functionType.parse(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, functionType.get()));
		pdb.popDependencyStack();
		name.parse(reader);
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(pdb.getTypeRecord(parentTypeIndex.get()));
		myBuilder.append("::");
		myBuilder.append(name);
		pdb.getTypeRecord(functionType.get()).emit(myBuilder, Bind.NONE);
		builder.append("MemberFunctionId for: ");
		builder.append(myBuilder);
	}

}
