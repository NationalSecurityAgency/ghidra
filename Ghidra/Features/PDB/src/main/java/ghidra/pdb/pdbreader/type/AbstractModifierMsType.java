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

public abstract class AbstractModifierMsType extends AbstractMsType {

	protected AbstractTypeIndex modifiedTypeIndex;
	protected int attributes;

	protected boolean isConst;
	protected boolean isVolatile;
	protected boolean isUnaligned;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractModifierMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parseFields(reader);
		processAttributes(attributes);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, modifiedTypeIndex.get()));
		pdb.popDependencyStack();
		reader.skipPadding();
	}

	/**
	 * Returns the record type index of the type that this modifier type modifies.
	 * @return The record type index of the type that is this modifier type modifies.
	 */
	public int getModifiedTypeIndex() {
		return modifiedTypeIndex.get();
	}

	/**
	 * Returns the {@link AbstractMsType} that this modifier type modifies.
	 * @return The type that is modified.
	 */
	public AbstractMsType getModifiedType() {
		return pdb.getTypeRecord(modifiedTypeIndex.get());
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder modBuilder = new StringBuilder();
		modBuilder.append(isConst ? "const " : "");
		modBuilder.append(isVolatile ? "volatile " : "");
		modBuilder.append(isUnaligned ? "__unaligned " : ""); // Not in API.
		modBuilder.append(getModifiedType());
		modBuilder.append(" ");
		builder.insert(0, modBuilder);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #modifiedTypeIndex}.
	 */
	protected abstract void create();

	/**
	 * Parses the fields for this type.
	 * <P>
	 * Implementing class must initialize {@link #modifiedTypeIndex} and {@link #attributes}.
	 * @param reader {@link PdbByteReader} from which the fields are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

	/**
	 * Internal method to process the integer attributes value into individual components.
	 * @param atts Attributes field to be parsed/processed.
	 */
	protected void processAttributes(int atts) {
		isConst = ((atts & 0x0001) == 0x0001);
		atts >>= 1;
		isVolatile = ((atts & 0x0001) == 0x0001);
		atts >>= 1;
		isUnaligned = ((atts & 0x0001) == 0x0001);
	}

}
