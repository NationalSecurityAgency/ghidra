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

import java.math.BigInteger;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

public class VectorMsType extends AbstractMsType {

	public static final int PDB_ID = 0x151b;

	private AbstractTypeIndex elementTypeIndex;
	private long count;
	//TODO: not sure about the following.
	private BigInteger size;
	private AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public VectorMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		elementTypeIndex = new TypeIndex32();
		name = new StringNt();

		elementTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, elementTypeIndex.get()));
		pdb.popDependencyStack();
		count = reader.parseUnsignedIntVal();
		//TODO: not sure about the following.
		size = reader.parseNumeric();
		name.parse(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the size of this vector type
	 * @return Size of the vector.
	 */
	public BigInteger getSize() {
		return size;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append(String.format("vector: %s[<%s> %d]", name.get(),
			pdb.getTypeRecord(elementTypeIndex.get()), count));
	}

}
