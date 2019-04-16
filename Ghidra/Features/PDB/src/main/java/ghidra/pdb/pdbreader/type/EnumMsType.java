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
 * This class represents the <B>MsType</B> flavor of Enum type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class EnumMsType extends AbstractEnumMsType {

	public static final int PDB_ID = 0x1507;

	protected AbstractString mangledName;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public EnumMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the mangled name field
	 * @return Mangled name.
	 */
	public String getMangledName() {
		return mangledName.get();
	}

	@Override
	protected void create() {
		fieldDescriptorListTypeIndex = new TypeIndex32();
		underlyingTypeIndex = new TypeIndex32();
		name = new StringNt();
		// Additional initialization
		mangledName = new StringNt();
	}

	@Override
	protected void parseFields(PdbByteReader reader) throws PdbException {
		numElements = reader.parseUnsignedShortVal();
		property = new MsProperty(reader);
		underlyingTypeIndex.parse(reader);
		fieldDescriptorListTypeIndex.parse(reader);
		if (reader.hasMoreNonPad()) {
			name.parse(reader);
			//System.out.println(name);
			if (reader.hasMoreNonPad()) {
				// Additional parsing
				mangledName.parse(reader);
				//System.out.println(mangledName);
			}
//			// DO NOT REMOVE
//			// The following code is for developmental investigations;
//			//  set break point on "int a = 1;" instead of a
//			//  conditional break point.
//			else if (reader.hasMore()) {
//				int a = 1;
//				a = a + 1;
//			}
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
//		name.parse(reader);
//		mangledName.parse(reader);
//		reader.skipPadding();
	}

}
