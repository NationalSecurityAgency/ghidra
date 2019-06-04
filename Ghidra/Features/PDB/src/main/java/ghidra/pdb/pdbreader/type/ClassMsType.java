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

/**
 * This class represents the <B>MsType</B> flavor of C++ Class type.
 * <P>
 * Note that class, struct, and interface are very closed related and have many of the same
 *  constructs and parsing procedures.  However, they are separate.  If any of the internals
 *  of one of these is changed, it is highly suggested that the others be changed as well as
 *  there is not code-shared between these other than by code duplication.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class ClassMsType extends AbstractClassMsType {

	public static final int PDB_ID = 0x1504;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public ClassMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void create() {
		fieldDescriptorListTypeIndex = new TypeIndex32();
		derivedFromListTypeIndex = new TypeIndex32(); // Can be zero if none.
		vShapeTableTypeIndex = new TypeIndex32();
		name = new StringNt(pdb);
		mangledName = new StringNt(pdb);
	}

	@Override
	protected void parseFields(PdbByteReader reader) throws PdbException {
		count = reader.parseUnsignedShortVal();
		property = new MsProperty(reader);
		fieldDescriptorListTypeIndex.parse(reader);
		derivedFromListTypeIndex.parse(reader);
		vShapeTableTypeIndex.parse(reader);
		//TODO: has more... guessing below
		size = reader.parseNumeric();
		if (reader.hasMoreNonPad()) {
			name.parse(reader);
			//System.out.println(name);
			if (reader.hasMoreNonPad()) {
				mangledName.parse(reader);
				//System.out.println(mangledName);
			}
		}
//		// DO NOT REMOVE
//		// The following code is for developmental investigations;
//		//  set break point on "int a = 1;" instead of a
//		//  conditional break point.
//		else {
//			int a = 1;
//			a = a + 1;
//		}
		reader.skipPadding();
	}

}
