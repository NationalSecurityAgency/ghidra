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

public class BaseInterfaceMsType extends AbstractMsType {

	public static final int PDB_ID = 0x151a;

	private AbstractTypeIndex baseClassIndex;
	private ClassFieldMsAttributes attribute;
	private BigInteger offset;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public BaseInterfaceMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		baseClassIndex = new TypeIndex32();
		attribute = new ClassFieldMsAttributes(reader);
		baseClassIndex.parse(reader);
		this.pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, baseClassIndex.get()));
		this.pdb.popDependencyStack();
		offset = reader.parseNumeric();
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		attribute.emit(builder);
		builder.append(":");
		builder.append(pdb.getTypeRecord(baseClassIndex.get()));
		builder.append("<@");
		builder.append(offset);
		builder.append(">");
	}

}
