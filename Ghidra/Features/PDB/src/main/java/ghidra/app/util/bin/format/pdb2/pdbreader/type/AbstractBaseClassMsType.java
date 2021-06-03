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
 * This class represents various flavors of Base Class type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractBaseClassMsType extends AbstractMsType implements MsTypeField {

	protected RecordNumber baseClassRecordNumber;
	protected ClassFieldMsAttributes attribute;
	protected BigInteger offset;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractBaseClassMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param baseClassRecordNumber the {@link RecordNumber} of the base class 
	 * @param offset the offset
	 * @param attribute the {@link ClassFieldMsAttributes}.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractBaseClassMsType(AbstractPdb pdb, RecordNumber baseClassRecordNumber, long offset,
			ClassFieldMsAttributes attribute) throws PdbException {
		super(pdb, null);
		this.baseClassRecordNumber = baseClassRecordNumber;
		this.offset = BigInteger.valueOf(offset);
		this.attribute = attribute;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		attribute.emit(builder);
		builder.append(":");
		builder.append(pdb.getTypeRecord(baseClassRecordNumber));
		builder.append("<@");
		builder.append(offset);
		builder.append(">");
	}

	/**
	 * Returns the offset of the base class within the inheriting class.
	 * @return the offset;
	 */
	public BigInteger getOffset() {
		return offset;
	}

	/**
	 * Returns the attributes of the base class within the inheriting class.
	 * @return the attributes;
	 */
	public ClassFieldMsAttributes getAttributes() {
		return attribute;
	}

	/**
	 * Returns the type index of the base class.
	 * @return the type index;
	 */
	public RecordNumber getBaseClassRecordNumber() {
		return baseClassRecordNumber;
	}

}
