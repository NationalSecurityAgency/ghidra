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
 * This class represents various flavors of Enum type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractEnumMsType extends AbstractMsType {

	protected int numElements;
	protected MsProperty property;
	protected AbstractTypeIndex underlyingTypeIndex;
	protected AbstractTypeIndex fieldDescriptorListTypeIndex;
	protected AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractEnumMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parseFields(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, underlyingTypeIndex.get()));
		pdb.popDependencyStack();
		if (fieldDescriptorListTypeIndex.get() != 0) {
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, fieldDescriptorListTypeIndex.get()));
			pdb.popDependencyStack();
		}
		reader.skipPadding();
	}

	/**
	 * Returns the name of this enum type.
	 * @return Name type of the enum type.
	 */
	@Override
	public String getName() {
		return name.get();
	}

	/**
	 * Returns the number of elements in this Enum.
	 * @return Number of elements in this Enum.
	 */
	public int getNumElements() {
		return numElements;
	}

	/**
	 * Returns the type index of the underlying type of this Enum.
	 * @return Type index of the underlying type.
	 */
	public int getUnderlyingTypeIndex() {
		return underlyingTypeIndex.get();
	}

	/**
	 * Returns the type index of the field descriptor list of this Enum
	 * @return Type index of the field descriptor list.
	 */
	public int getFieldDescriptorListTypeIndex() {
		return fieldDescriptorListTypeIndex.get();
	}

	/**
	 * Returns the MsProperty of this Enum
	 * @return {@link MsProperty} of this Enum.
	 */
	public MsProperty getMsProperty() {
		return property;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append("enum ");
		myBuilder.append(name);
		myBuilder.append("<");
		myBuilder.append(numElements);
		myBuilder.append(",");
		myBuilder.append(pdb.getTypeRecord(underlyingTypeIndex.get()));
		myBuilder.append(",");
		myBuilder.append(property);
		myBuilder.append(">");
		if (fieldDescriptorListTypeIndex.get() != 0) {
			myBuilder.append(pdb.getTypeRecord(fieldDescriptorListTypeIndex.get()));
		}
		myBuilder.append(" ");
		builder.insert(0, myBuilder);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #fieldDescriptorListTypeIndex},
	 *  {@link #underlyingTypeIndex}, and {@link #name}.
	 */
	protected abstract void create();

	/**
	 * Parses the fields of the enum type.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, allocate/parse
	 * {@link #property}; also parse {@link #numElements}, {@link #underlyingTypeIndex},
	 * {@link #fieldDescriptorListTypeIndex}, and {@link #name}.
	 * @param reader {@link PdbByteReader} from which to parse the fields.
	 * @throws PdbException upon error parsing a field.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

}
