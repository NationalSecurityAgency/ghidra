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
 * A length-prefixed string {@link DataType} (max 64k bytes) with char size of 1 byte,
 * user setable {@link CharsetSettingsDefinition charset} (default ASCII),
 * unbounded (ignores containing field size, relies on embedded length value).
 * <p>
 */
public class PascalStringDataType extends AbstractStringDataType {

	public static final PascalStringDataType dataType = new PascalStringDataType();

	public PascalStringDataType() {
		this(null);
	}

	public PascalStringDataType(DataTypeManager dtm) {
		super("PascalString", // data type name
			"p_string", // mnemonic
			"P_STRING", // default label
			"P_STR", // default label prefix
			"p", // default abbrev label prefix
			"String (Pascal 64k)", // description
			USE_CHARSET_DEF_DEFAULT, // charset
			ByteDataType.dataType, // replacement data type
			StringLayoutEnum.PASCAL_64k, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PascalStringDataType(dtm);
	}
}
