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
package ghidra.program.model.data;

/**
 * Basic implementation for an Signed LongLong Integer dataType 
 */
public class UnsignedLongLongDataType extends AbstractIntegerDataType {

	private final static long serialVersionUID = 1;

	/** A statically defined UnsignedLongLongDataType instance.*/
	public final static UnsignedLongLongDataType dataType = new UnsignedLongLongDataType();

	public UnsignedLongLongDataType() {
		this(null);
	}

	public UnsignedLongLongDataType(DataTypeManager dtm) {
		super("ulonglong", false, dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		return getDataOrganization().getLongLongSize();
	}

	/**
	 * @see ghidra.program.model.data.DataType#hasLanguageDependantLength()
	 */
	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Unsigned Long Long Integer (compiler-specific size)";
	}

	@Override
	public String getCDeclaration() {
		return C_UNSIGNED_LONGLONG;
	}

	@Override
	public LongLongDataType getOppositeSignednessDataType() {
		return LongLongDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedLongLongDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedLongLongDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(getName(), "unsigned long long", false); // standard C-primitive type with modified name
	}

}
