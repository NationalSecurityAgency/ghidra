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
import mdemangler.MDMang;

/**
 * This class represents various flavors of Complex type.  Not Complex in terms of real and
 * imaginary components, but complex in terms of having {@link MsProperty} and other similar
 * aspects.  The term "Complex" was chosen to mimic what data types are called in the
 * {@link MDMang} group that has the same types, which are generally Composites, Interfaces, and
 * Enums.
 */
public abstract class AbstractComplexMsType extends AbstractMsType {
	// -1 is a flag to prevent the count from being emitted, which is what is desired if there
	// is not a count field for the child type.  0 and up are valid values.
	protected int count = -1;
	protected RecordNumber fieldDescriptorListRecordNumber;
	protected MsProperty property;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractComplexMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param count number of field elements
	 * @param fieldDescriptorListRecordNumber {@link RecordNumber} of field list 
	 * @param property {@link MsProperty} of this type
	 * @param name the name of this type
	 */
	public AbstractComplexMsType(AbstractPdb pdb, int count,
			RecordNumber fieldDescriptorListRecordNumber, MsProperty property, String name) {
		super(pdb, null);
		this.count = count;
		this.fieldDescriptorListRecordNumber = fieldDescriptorListRecordNumber;
		this.property = property;
		this.name = name;
	}

	/**
	 * Returns the number of elements.
	 * @return Number of elements.
	 */
	public int getNumElements() {
		return count;
	}

	/**
	 * Returns the record number of the field descriptor list used for this composite.
	 * @return Record number of the field descriptor list.
	 */
	public RecordNumber getFieldDescriptorListRecordNumber() {
		return fieldDescriptorListRecordNumber;
	}

	/**
	 * Returns the field type for the fields of this class.  Returns null if none.
	 * @return {@link AbstractMsType} type of the field type or null if none.
	 */
	public AbstractMsType getFieldDescriptorListType() {
		return pdb.getTypeRecord(fieldDescriptorListRecordNumber);
	}

	/**
	 * Returns the MsProperty of this composite.
	 * @return {@link MsProperty} of this composite.
	 */
	public MsProperty getMsProperty() {
		return property;
	}

	/**
	 * Returns the name of this type.
	 * @return Name type of the type.
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the type name of this complex type.
	 * @return Type of the complex type.
	 */
	public String getTypeName() {
		return getTypeString();
	}

	/**
	 * Returns the type of complex type.
	 * @return Standard (C/C++) name for the type of complex type.
	 */
	protected abstract String getTypeString();

}
