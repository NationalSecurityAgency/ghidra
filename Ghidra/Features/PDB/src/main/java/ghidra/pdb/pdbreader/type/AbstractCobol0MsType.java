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
 * This class represents various flavors of Cobol0 type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractCobol0MsType extends AbstractMsType {

	protected AbstractTypeIndex parentTypeIndex;
	// TODO: This is made up data.  API and examples are unknown.
	protected byte[] data;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractCobol0MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		parentTypeIndex = create();
		parentTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, parentTypeIndex.get()));
		pdb.popDependencyStack();
		data = reader.parseBytesRemaining();
	}

	/**
	 * Returns the type that is pointed to.
	 * @return {@link AbstractMsType} type that is pointed to by this pointer.
	 */
	public AbstractMsType getParentType() {
		return pdb.getTypeRecord(parentTypeIndex.get());
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("Cobol0MsType\n");
		builder.append(String.format("  parent type index: %s\n", getParentType()));
		builder.append(String.format("  additional data length: %d\n", data.length));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * @return the {@link AbstractTypeIndex} type necessary for the {@link #parentTypeIndex} in the
	 * concrete class.
	 */
	protected abstract AbstractTypeIndex create();

}
