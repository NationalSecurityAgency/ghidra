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

import java.util.List;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Derived Class List type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDerivedClassListMsType extends AbstractMsType {

	protected List<AbstractTypeIndex> typeIndexList;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractDerivedClassListMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		typeIndexList = parseTypeIndexList(reader);
		for (AbstractTypeIndex typeIndex : typeIndexList) {
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
			pdb.popDependencyStack();
		}
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		DelimiterState ds = new DelimiterState("", ", ");
		for (AbstractTypeIndex typeIndex : typeIndexList) {
			AbstractMsType type = pdb.getTypeRecord(typeIndex.get());
			builder.append(ds.out(true, type.toString()));
		}
	}

	/**
	 * Parses the Type Index List.
	 * @param reader {@link PdbByteReader} that is deserialized.
	 * @return Type indices.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract List<AbstractTypeIndex> parseTypeIndexList(PdbByteReader reader)
			throws PdbException;

}
