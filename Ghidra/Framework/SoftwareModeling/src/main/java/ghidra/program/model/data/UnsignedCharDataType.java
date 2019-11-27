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
 * Provides a definition of a primitive unsigned char data type.
 * While in most environment the size is one 8-bit byte, this
 * can vary based upon data organization imposed by the 
 * associated data type manager.
 */
public class UnsignedCharDataType extends CharDataType {
	private final static long serialVersionUID = 1;

	public static final UnsignedCharDataType dataType = new UnsignedCharDataType();

	/**
	 * Constructs a new unsigned char datatype.
	 */
	public UnsignedCharDataType() {
		this(null);
	}

	public UnsignedCharDataType(DataTypeManager dtm) {
		super("uchar", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned Character (ASCII)";
	}

	@Override
	public UnsignedCharDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedCharDataType(dtm);
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "UCHAR";
	}

	@Override
	public String getCDeclaration() {
		return "unsigned char";
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(getName(), getCDeclaration(), false); // standard C-primitive type with modified name
	}
}
