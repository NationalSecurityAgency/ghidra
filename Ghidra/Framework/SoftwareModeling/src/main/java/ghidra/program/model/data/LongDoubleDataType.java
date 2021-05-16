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
 * Provides a definition of a Long Double within a program.
 */
public class LongDoubleDataType extends AbstractFloatDataType {

	public static final LongDoubleDataType dataType = new LongDoubleDataType();

	/**
	 * Creates a Double data type.
	 */
	public LongDoubleDataType() {
		this(null);
	}

	public LongDoubleDataType(DataTypeManager dtm) {
		super("longdouble", dtm);
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new LongDoubleDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(getName(), "long double", false); // standard C-primitive type with modified name
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public int getLength() {
		return getDataOrganization().getLongDoubleSize();
	}
}
