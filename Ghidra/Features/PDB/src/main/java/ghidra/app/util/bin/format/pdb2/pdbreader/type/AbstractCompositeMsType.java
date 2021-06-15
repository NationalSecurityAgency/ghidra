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
 * This class represents various flavors of Composite type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractCompositeMsType extends AbstractComplexMsType {

	protected RecordNumber derivedFromListRecordNumber; // Zero if none. Not used by union. 
	protected RecordNumber vShapeTableRecordNumber; // Not used by union.
	//TODO: has more... guessing below
	protected BigInteger size;
	protected String mangledName; // Used by MsType (not used by 16MsType or StMsType?)

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractCompositeMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
		//reader.skipPadding();
	}

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param count count number of field elements
	 * @param fieldListRecordNumber {@link RecordNumber} of the field list.
	 * @param property {@link MsProperty} of this composite.
	 * @param size size of the composite
	 * @param derivedFromRecordNumber {@link RecordNumber} of the derived-from type.
	 * @param vShapeTableRecordNumber {@link RecordNumber} of the vShapeTable.
	 * @param name name of the composite
	 * @param mangledName mangled name (if it exists)
	 */
	public AbstractCompositeMsType(AbstractPdb pdb, int count, RecordNumber fieldListRecordNumber,
			MsProperty property, long size, RecordNumber derivedFromRecordNumber,
			RecordNumber vShapeTableRecordNumber, String name, String mangledName) {
		super(pdb, null);
		//super(pdb, null, count, fieldListRecordNumber, property, name);
		this.name = name;
		this.mangledName = mangledName;
		this.size = BigInteger.valueOf(size);
		this.property = property;
		this.fieldDescriptorListRecordNumber = fieldListRecordNumber;
		this.derivedFromListRecordNumber = derivedFromRecordNumber;
		this.vShapeTableRecordNumber = vShapeTableRecordNumber;
	}

	/**
	 * Returns the mangled name within this composite.
	 * @return Mangled name.
	 */
	public String getMangledName() {
		return mangledName;
	}

	/**
	 * Returns the record number of the derived-from list of types.
	 * @return Record number of the derived-from list of types.
	 */
	public RecordNumber getDerivedFromListRecordNumber() {
		return derivedFromListRecordNumber;
	}

	/**
	 * Returns the record number of the VShape table.
	 * @return Record number of the VShape table.
	 */
	public RecordNumber getVShapeTableRecordNumber() {
		return vShapeTableRecordNumber;
	}

	/**
	 * Returns the size of this composite
	 * @return Size of this composite.
	 */
	@Override
	public BigInteger getSize() {
		return size;
	}

	//TODO: ??? nothing done with mangledName
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
		myBuilder.append(property);
		myBuilder.append(">");
		AbstractMsType fieldType = getFieldDescriptorListType();
		if (fieldType instanceof PrimitiveMsType && ((PrimitiveMsType) fieldType).isNoType()) {
			myBuilder.append("{}");
		}
		else {
			myBuilder.append(fieldType);
		}
		myBuilder.append(" ");
		builder.insert(0, myBuilder);
	}

}
