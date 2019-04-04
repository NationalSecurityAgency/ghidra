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
 * Note that class, struct, and interface are very closed related and have many of the same
 *  constructs and parsing procedures.  However, they are separate.  If any of the internals
 *  of one of these is changed, it is highly suggested that the others be changed as well as
 *  there is not code-shared between these other than by code duplication.
 */
public class Structure16MsType extends AbstractStructureMsType {

	public static final int PDB_ID = 0x0005;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public Structure16MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void create() {
		fieldDescriptorListTypeIndex = new TypeIndex16();
		derivedFromListTypeIndex = new TypeIndex16(); // Can be zero if none.
		vShapeTableTypeIndex = new TypeIndex16();
		name = new StringSt();
		mangledName = new StringSt();
	}

	@Override
	protected void parseFields(PdbByteReader reader) throws PdbException {
		//Different order
		count = reader.parseUnsignedShortVal();
		fieldDescriptorListTypeIndex.parse(reader);
		property = new MsProperty(reader);
		derivedFromListTypeIndex.parse(reader);
		vShapeTableTypeIndex.parse(reader);
		size = reader.parseNumeric();
		name.parse(reader);
	}

}
