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
 * 32-bit signed integer (C99 Standard type {@code int32_t})
 */
public class Int32TDataType extends AbstractSignedIntegerDataType {

	public final static Int32TDataType dataType = new Int32TDataType();

	public Int32TDataType() {
		this(null);
	}

	public Int32TDataType(DataTypeManager dtm) {
		super("int32_t", dtm);
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getDescription() {
		return "Signed 32-bit Integer";
	}

	@Override
	public String getCDeclaration() {
		return null;
	}

	@Override
	public UInt32TDataType getOppositeSignednessDataType() {
		return UInt32TDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Int32TDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Int32TDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
