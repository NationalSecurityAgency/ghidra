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
 * A class for a specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class Pointer16MsType extends AbstractPointerMsType {

	public static final int PDB_ID = 0x0002;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public Pointer16MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void create() {
		underlyingTypeIndex = new TypeIndex16();
		memberPointerContainingClassIndex = new TypeIndex16();
		baseSymbol = new StringSt();
		name = new StringSt();
	}

	@Override
	protected void parsePointerBody(PdbByteReader reader) throws PdbException {
		parseAttributes(reader);
		underlyingTypeIndex.parse(reader);
	}

	@Override
	protected void parseAttributes(PdbByteReader reader) throws PdbException {
		int attributes1 = reader.parseUnsignedByteVal();
		int attributes2 = reader.parseUnsignedByteVal();
		pointerTypeAttribute = attributes1 & 0x001f;
		attributes1 >>= 5;
		pointerModeAttribute = attributes1 & 0x0007;

		isFlat = ((attributes2 & 0x0001) == 0x0001);
		attributes2 >>= 1;
		isVolatile = ((attributes2 & 0x0001) == 0x0001);
		attributes2 >>= 1;
		isConst = ((attributes2 & 0x0001) == 0x0001);
		attributes2 >>= 1;
		isUnaligned = ((attributes2 & 0x0001) == 0x0001);
	}

	@Override
	protected int getMySize() {
		return 2;
	}

}
