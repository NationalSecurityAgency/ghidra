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
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.CategoryIndex;

/**
 * This class represents the <B>MsType</B> flavor of String ID type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class StringIdMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1605;

	private int idOfSubstringIDList;
	private String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a string.
	 */
	public StringIdMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		idOfSubstringIDList = reader.parseInt();
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.ITEM, idOfSubstringIDList));
		pdb.popDependencyStack();

		name = reader.parseNullTerminatedString();
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		//TODO: could be wrong (including how substrings are concatenated and added), but it
		// appears to work correctly like this.
		if (idOfSubstringIDList != 0) {
			AbstractMsType subStringList = pdb.getItemRecord(idOfSubstringIDList);
			if (!(subStringList instanceof SubstringListMsType)) {
				return; //fail quietly.
			}
			builder.append(subStringList);

		}
		// The API shows this as an else on the 'if' and I found a symbol which would get
		//  truncated without this as a stand-alone statement.  MSFT appears to be wrong
		//  in their handling of the PDB here.
		// Example is from build1264_Z7/cn3.pdb in testPdbTPI800UsingAutoClose_1().
		builder.append(name);
	}

}
