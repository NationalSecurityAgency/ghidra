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

public abstract class AbstractCompositeMsType extends AbstractMsType {

	protected int count;
	protected AbstractTypeIndex fieldDescriptorListTypeIndex;
	protected MsProperty property;
	protected AbstractTypeIndex derivedFromListTypeIndex; // Zero if none. Not used by union. 
	protected AbstractTypeIndex vShapeTableTypeIndex; // Not used by union.
	//TODO: has more... guessing below
	protected BigInteger size;
	protected AbstractString name;
	protected AbstractString mangledName; // Used by MsType (not used by 16MsType or StMsType?)

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractCompositeMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parseFields(reader);
		reader.skipPadding();
		if (fieldDescriptorListTypeIndex.get() != 0) {
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, fieldDescriptorListTypeIndex.get()));
			pdb.popDependencyStack();
		}
		if ((derivedFromListTypeIndex != null) && (derivedFromListTypeIndex.get() != 0)) {
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, derivedFromListTypeIndex.get()));
			pdb.popDependencyStack();
		}
		if ((vShapeTableTypeIndex != null) && (vShapeTableTypeIndex.get() != 0)) {
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, vShapeTableTypeIndex.get()));
			pdb.popDependencyStack();
		}
	}

	/**
	 * Returns the name of this composite.
	 * @return Name type of the composite.
	 */
	@Override
	public String getName() {
		return name.get();
	}

	/**
	 * Returns the mangled name within this composite.
	 * @return Mangled name.
	 */
	public String getMangledName() {
		return mangledName.get();
	}

	/**
	 * Returns the type index of the field descriptor list used for this composite.
	 * @return Type index of the field descriptor list.
	 */
	public int getFieldDescriptorListTypeIndex() {
		return fieldDescriptorListTypeIndex.get();
	}

	/**
	 * Returns the type index of the derived-from list of types.
	 * @return Type index of the derived-from list of types.
	 */
	public int getDerivedFromListTypeIndex() {
		if (derivedFromListTypeIndex == null) {
			return 0;
		}
		return derivedFromListTypeIndex.get();
	}

	/**
	 * Returns the type index of the VShape table.
	 * @return Type index of the VShape table.
	 */
	public int getVShapeTableTypeIndex() {
		if (vShapeTableTypeIndex == null) {
			return 0;
		}
		return vShapeTableTypeIndex.get();
	}

	/**
	 * Returns the MsProperty of this composite.
	 * @return {@link MsProperty} of this composite.
	 */
	public MsProperty getMsProperty() {
		return property;
	}

	/**
	 * Returns the size of this composite
	 * @return Size of this composite.
	 */
	public BigInteger getSize() {
		return size;
	}

	/**
	 * Returns the field type for the fields of this class.  Returns null if none.
	 * @return {@link AbstractMsType} type of the field type or null if none.
	 */
	public AbstractMsType getFieldDescriptorListType() {
		return pdb.getTypeRecord(fieldDescriptorListTypeIndex.get());
	}

	//TODO: ??? nothing done with mangledName
	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(getTypeString());
		myBuilder.append(" ");
		myBuilder.append(name);
		myBuilder.append("<");
		myBuilder.append(count);
		myBuilder.append(",");
		myBuilder.append(property);
		myBuilder.append(">");
		AbstractMsType fieldType = getFieldDescriptorListType();
		myBuilder.append(fieldType);
		myBuilder.append(" ");
		builder.insert(0, myBuilder);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #fieldDescriptorListTypeIndex}, {@link #name},
	 *  and {@link #mangledName}.  It can optionally initialize {@link #derivedFromListTypeIndex}
	 *  and {@link #vShapeTableTypeIndex}, but if it does, it must also make sure they are
	 *  parsed in {@link #parseFields(PdbByteReader)}.
	 */
	protected abstract void create();

	/**
	 * Parsed the fields for this type.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, allocate/parse
	 * {@link #property}; also parse {@link #count}, {@link #fieldDescriptorListTypeIndex},
	 * and {@link #size}; and optionally parse, if non-pad data present--and in the appropriate
	 * interspersed order, {@link #derivedFromListTypeIndex}, {@link #vShapeTableTypeIndex},
	 * {@link #name}, and {@link #mangledName}.
	 * @param reader {@link PdbByteReader} from which the fields are parsed.
	 * @throws PdbException upon error parsing a field.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

	/**
	 * Returns the type of composite.
	 * @return Standard (C/C++) name for the type of composite.
	 */
	protected abstract String getTypeString();

}
