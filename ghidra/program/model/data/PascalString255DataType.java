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
 * A length-prefixed string {@link DataType} (max 255 bytes) with char size of 1 byte,
 * user setable {@link CharsetSettingsDefinition charset} (default ASCII),
 * unbounded (ignores containing field size, relies on embedded length value).
 * <p>
 */
public class PascalString255DataType extends AbstractStringDataType {

	public static final PascalString255DataType dataType = new PascalString255DataType();

	public PascalString255DataType() {
		this(null);
	}

	public PascalString255DataType(DataTypeManager dtm) {
		super("PascalString255", // data type name
			"p_string255", // mnemonic
			"PASCAL255", // default label
			"P_STR", // default label prefix
			"p", // default abbrev label prefix
			"String (Pascal 255)", // description
			USE_CHARSET_DEF_DEFAULT, // charset
			ByteDataType.dataType, // replacement data type
			StringLayoutEnum.PASCAL_255, // StringLayoutEnum
			dtm// data type manager
		);
	}

	public DataType copy(boolean retainIdentity) {
		return new PascalString255DataType();
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PascalString255DataType(dtm);
	}
}
