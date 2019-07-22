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
 * Provides a definition of a primitive signed char data type.
 * While in most environment the size is one 8-bit byte, this
 * can vary based upon data organization imposed by the 
 * associated data type manager.
 */
public class SignedCharDataType extends CharDataType {
	private final static long serialVersionUID = 1;

	public static final SignedCharDataType dataType = new SignedCharDataType();

	/**
	 * Constructs a new signed char datatype.
	 */
	public SignedCharDataType() {
		this(null);
	}

	public SignedCharDataType(DataTypeManager dtm) {
		super("schar", true, dtm);
	}

	@Override
	public String getDescription() {
		return "Signed Character (ASCII)";
	}

	@Override
	public SignedCharDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new SignedCharDataType(dtm);
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "SCHAR";
	}

	@Override
	public String getCDeclaration() {
		return "signed char";
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(getName(), getCDeclaration(), false); // standard C-primitive type with modified name
	}
}
