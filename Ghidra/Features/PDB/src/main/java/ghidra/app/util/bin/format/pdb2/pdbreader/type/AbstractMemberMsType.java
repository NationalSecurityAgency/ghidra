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

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Member type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractMemberMsType extends AbstractMsType implements MsTypeField {

	protected ClassFieldMsAttributes attribute;
	protected RecordNumber fieldTypeRecordNumber;
	protected BigInteger offset;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractMemberMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	public AbstractMemberMsType(AbstractPdb pdb, String name, long offset,
			RecordNumber fieldTypeRecordNumber, ClassFieldMsAttributes attribute) {
		super(pdb, null);
		this.name = name;
		this.offset = BigInteger.valueOf(offset);
		this.fieldTypeRecordNumber = fieldTypeRecordNumber;
		this.attribute = attribute;
	}

	/**
	 * Returns the name of this member type.
	 * @return Name type of the member type.
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the offset of the member.
	 * @return The offset of the member.
	 */
	public BigInteger getOffset() {
		return offset;
	}

	/**
	 * Returns the attributes of the member.
	 * @return The attributes of the member.
	 */
	public ClassFieldMsAttributes getAttribute() {
		return attribute;
	}

	/**
	 * Returns the record number of the field data type.
	 * @return Record number of the field data type.
	 */
	public RecordNumber getFieldTypeRecordNumber() {
		return fieldTypeRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(attribute);
		builder.append(": ");
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(name);
		pdb.getTypeRecord(fieldTypeRecordNumber).emit(myBuilder, Bind.NONE);
		builder.append(myBuilder);
		builder.append("<@");
		builder.append(offset);
		builder.append(">");
	}

}
