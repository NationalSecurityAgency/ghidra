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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Modifier type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractModifierMsType extends AbstractMsType {

	protected RecordNumber modifiedRecordNumber;
	protected int attributes;

	protected boolean isConst;
	protected boolean isVolatile;
	protected boolean isUnaligned;

	/**
	 * Constructor from PdbByteReader for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractModifierMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	/**
	 * Constructor from values for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param modifiedRecordNumber RecordNumber of modified type.
	 * @param isConst {@code true} if constant.
	 * @param isVolatile {@code true} if volatile.
	 * @param isUnaligned  {@code true} if not aligned.
	 */
	public AbstractModifierMsType(AbstractPdb pdb, RecordNumber modifiedRecordNumber,
			boolean isConst, boolean isVolatile, boolean isUnaligned) {
		super(pdb, null);
		this.modifiedRecordNumber = modifiedRecordNumber;
		this.isConst = isConst;
		this.isVolatile = isVolatile;
		this.isUnaligned = isUnaligned;
	}

	/**
	 * Returns the record number of the type that this modifier type modifies.
	 * @return The record number of the type that is this modifier type modifies.
	 */
	public RecordNumber getModifiedRecordNumber() {
		return modifiedRecordNumber;
	}

	/**
	 * Returns the {@link AbstractMsType} that this modifier type modifies.
	 * @return The type that is modified.
	 */
	public AbstractMsType getModifiedType() {
		return pdb.getTypeRecord(modifiedRecordNumber);
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
