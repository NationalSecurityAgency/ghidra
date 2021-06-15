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
 * This class represents various flavors of Enum type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractEnumMsType extends AbstractComplexMsType {

	private static final String TYPE_STRING = "enum";

	protected RecordNumber underlyingRecordNumber;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractEnumMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	/**
	 * Constructor for this type (for testing).
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param name name for the type.
	 * @param underlyingRecordNumber {@link RecordNumber} of underlying type.
	 * @param fieldDescriptorRecordNumber {@link RecordNumber} of field descriptor. 
	 * @param property {@link MsProperty} of this enum.
	 * @param numElements number of elements in the enum.
	 */
	public AbstractEnumMsType(AbstractPdb pdb, String name, RecordNumber underlyingRecordNumber,
			RecordNumber fieldDescriptorRecordNumber, MsProperty property, int numElements) {
		super(pdb, null);
		this.name = name;
		this.underlyingRecordNumber = underlyingRecordNumber;
		this.fieldDescriptorListRecordNumber = fieldDescriptorRecordNumber;
		this.property = property;
		this.count = numElements;
	}

	/**
	 * Returns the record number of the underlying type of this Enum.
	 * @return Record number of the underlying type.
	 */
	public RecordNumber getUnderlyingRecordNumber() {
		return underlyingRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(getTypeString());
		myBuilder.append(" ");
		myBuilder.append(name);
		myBuilder.append("<");
		if (count != -1) {
			myBuilder.append(count);
			myBuilder.append(",");
		}
		myBuilder.append(pdb.getTypeRecord(underlyingRecordNumber));
		myBuilder.append(",");
		myBuilder.append(property);
		myBuilder.append(">");
		if (fieldDescriptorListRecordNumber != RecordNumber.NO_TYPE) {
			myBuilder.append(pdb.getTypeRecord(fieldDescriptorListRecordNumber));
		}
		myBuilder.append(" ");
		builder.insert(0, myBuilder);
	}

	@Override
	protected String getTypeString() {
		return TYPE_STRING;
	}

}
