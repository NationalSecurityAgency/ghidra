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
import ghidra.pdb.pdbreader.TypeIndex16;

/**
 * This class represents the <B>16MsType</B> flavor of C++ Indirect Virtual Base Class type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class IndirectVirtualBaseClass16MsType extends AbstractIndirectVirtualBaseClassMsType {

	public static final int PDB_ID = 0x0402;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public IndirectVirtualBaseClass16MsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void create() {
		directVirtualBaseClassTypeIndex = new TypeIndex16();
		virtualBasePointerTypeIndex = new TypeIndex16();
	}

	@Override
	protected void parseInitialFields(PdbByteReader reader) throws PdbException {
		directVirtualBaseClassTypeIndex.parse(reader);
		virtualBasePointerTypeIndex.parse(reader);
		attribute = new ClassFieldMsAttributes(reader);
	}

}
