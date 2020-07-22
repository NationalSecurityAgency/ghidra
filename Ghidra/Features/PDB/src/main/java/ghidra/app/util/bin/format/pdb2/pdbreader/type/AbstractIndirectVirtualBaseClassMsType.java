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
 * This class represents various flavors of C++ Indirect Virtual Base Class type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractIndirectVirtualBaseClassMsType extends AbstractMsType
		implements MsTypeField {

	protected RecordNumber directVirtualBaseClassRecordNumber;
	protected RecordNumber virtualBasePointerRecordNumber;
	protected ClassFieldMsAttributes attribute;
	protected BigInteger virtualBasePointerOffsetFromAddressPoint;
	protected BigInteger virtualBaseOffsetFromVBTable;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractIndirectVirtualBaseClassMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("<indirect ");
		builder.append(attribute);
		builder.append(": ");
		AbstractMsType type = pdb.getTypeRecord(directVirtualBaseClassRecordNumber);
		builder.append(type.getName());

		StringBuilder vbpBuilder = new StringBuilder();
		vbpBuilder.append("vbp");
		pdb.getTypeRecord(virtualBasePointerRecordNumber).emit(vbpBuilder, Bind.NONE);
		builder.append(vbpBuilder);
		builder.append("; offVbp=");
		builder.append(virtualBasePointerOffsetFromAddressPoint);
		builder.append("; offVbte=");
		builder.append(virtualBaseOffsetFromVBTable);
		builder.append("; >");
	}

	/**
	 * Returns the offset of the base base pointer within the class.
	 * @return the offset;
	 */
	public BigInteger getBasePointerOffset() {
		return virtualBasePointerOffsetFromAddressPoint;
	}

	/**
	 * Returns the virtual base offset from VB table.
	 * @return the offset;
	 */
	public BigInteger getBaseOffsetFromVbt() {
		return virtualBaseOffsetFromVBTable;
	}

	/**
	 * Returns the attributes of the base class within the inheriting class.
	 * @return the attributes;
	 */
	public ClassFieldMsAttributes getAttributes() {
		return attribute;
	}

	/**
	 * Returns the record number of the base class.
	 * @return the record number of the base class.
	 */
	public RecordNumber getBaseClassRecordNumber() {
		return directVirtualBaseClassRecordNumber;
	}

	/**
	 * Returns the record number of the virtual base pointer.
	 * @return the record number of the virtual base pointer.
	 */
	public RecordNumber getVirtualBasePointerRecordNumber() {
		return virtualBasePointerRecordNumber;
	}

}
