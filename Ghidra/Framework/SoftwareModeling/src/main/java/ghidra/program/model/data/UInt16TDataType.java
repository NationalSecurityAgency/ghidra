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
 * 16-bit unsigned integer (C99 Standard type {@code uint16_t})
 */
public class UInt16TDataType extends AbstractUnsignedIntegerDataType {

	public final static UInt16TDataType dataType = new UInt16TDataType();

	public UInt16TDataType() {
		this(null);
	}

	public UInt16TDataType(DataTypeManager dtm) {
		super("uint16_t", dtm);
	}

	@Override
	public int getLength() {
		return 2;
	}

	@Override
	public String getDescription() {
		return "Unsigned 16-bit Integer";
	}

	@Override
	public String getCDeclaration() {
		return null;
	}

	@Override
	public Int16TDataType getOppositeSignednessDataType() {
		return Int16TDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UInt16TDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UInt16TDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, false, dataOrganization, false);
	}
}
