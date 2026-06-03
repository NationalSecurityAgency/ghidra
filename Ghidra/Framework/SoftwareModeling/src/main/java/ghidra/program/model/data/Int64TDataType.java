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
 * 64-bit signed integer (C99 Standard type {@code int64_t})
 */
public class Int64TDataType extends AbstractSignedIntegerDataType {

	public final static Int64TDataType dataType = new Int64TDataType();

	public Int64TDataType() {
		this(null);
	}

	public Int64TDataType(DataTypeManager dtm) {
		super("int64_t", dtm);
	}

	@Override
	public int getLength() {
		return 8;
	}

	@Override
	public String getDescription() {
		return "Signed 64-bit Integer";
	}

	@Override
	public String getCDeclaration() {
		return null;
	}

	@Override
	public UInt64TDataType getOppositeSignednessDataType() {
		return UInt64TDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Int64TDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Int64TDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
