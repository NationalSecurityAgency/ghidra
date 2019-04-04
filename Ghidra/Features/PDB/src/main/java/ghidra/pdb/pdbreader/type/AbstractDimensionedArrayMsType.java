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

public abstract class AbstractDimensionedArrayMsType extends AbstractMsType {

	protected AbstractTypeIndex elementTypeIndex;
	protected AbstractTypeIndex dimensionInformation;
	protected AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractDimensionedArrayMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		elementTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, elementTypeIndex.get()));
		pdb.popDependencyStack();
		dimensionInformation.parse(reader);
		name.parse(reader);
		reader.skipPadding();
	}

	/**
	 * Returns the element type of this array.
	 * @return The AbstractMsType that is the base element type of the array.
	 */
	public AbstractMsType getElementType() {
		return pdb.getTypeRecord(elementTypeIndex.get());
	}

	/**
	 * Returns the dimension information of this array.
	 * @return The dimension information of the array.
	 */
	public int getIndexType() {
		return dimensionInformation.get();
	}

	/**
	 * Returns the name of this dimensioned array.
	 * @return Name of the dimensioned array.
	 */
	@Override
	public String getName() {
		return name.get();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (bind.ordinal() < Bind.ARRAY.ordinal()) {
			builder.insert(0, "(");
			builder.append(")");
		}
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append("<");
		myBuilder.append(dimensionInformation.get());
		myBuilder.append(">");

		builder.append("[");
		builder.append(myBuilder);
		builder.append("]");

		getElementType().emit(builder, Bind.ARRAY);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #elementTypeIndex}, {@link #dimensionInformation},
	 * and {@link #name}.
	 */
	protected abstract void create();

}
