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
 * 8-bit unsigned integer (C99 Standard type {@code uint8_t})
 */
public class UInt8TDataType extends AbstractUnsignedIntegerDataType {

	public final static UInt8TDataType dataType = new UInt8TDataType();

	public UInt8TDataType() {
		this(null);
	}

	public UInt8TDataType(DataTypeManager dtm) {
		super("uint8_t", dtm);
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public String getDescription() {
		return "Unsigned 8-bit Integer";
	}

	@Override
	public String getCDeclaration() {
		return null;
	}

	@Override
	public Int8TDataType getOppositeSignednessDataType() {
		return Int8TDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UInt8TDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UInt8TDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, false, dataOrganization, false);
	}
}
