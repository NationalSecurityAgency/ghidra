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

public class UserDefinedTypeSourceAndLineMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1606;

	private AbstractTypeIndex udtTypeIndex;
	private AbstractTypeIndex sourceFileNameStringIdIndex;
	private int lineNumber;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public UserDefinedTypeSourceAndLineMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		udtTypeIndex = new TypeIndex32();
		sourceFileNameStringIdIndex = new TypeIndex32();

		udtTypeIndex.parse(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, udtTypeIndex.get()));
		pdb.popDependencyStack();
		sourceFileNameStringIdIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.ITEM, sourceFileNameStringIdIndex.get()));
		pdb.popDependencyStack();

		lineNumber = reader.parseInt();
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No good API.
		// TODO: Think their hash stuff might be superfluous... will see...
		builder.append(UserDefinedTypeSourceAndLineMsType.class.getSimpleName());
		builder.append(", line: ");
		builder.append(lineNumber);
		builder.append(", SourceFileNameStringIdIndex: ");
		builder.append(pdb.getItemRecord(sourceFileNameStringIdIndex.get()).toString());
		builder.append(", type: ");
		builder.append(pdb.getTypeRecord(udtTypeIndex.get()));
	}

}
