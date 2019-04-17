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
 * A length-prefixed string {@link DataType} (max 64k bytes) with char size of 2 bytes,
 * {@link CharsetSettingsDefinition UTF-16} charset, unbounded
 * (ignores containing field size, relies on embedded length value).
 * <p>
 */
public class PascalUnicodeDataType extends AbstractStringDataType {

	public static final PascalUnicodeDataType dataType = new PascalUnicodeDataType();

	public PascalUnicodeDataType() {
		this(null);
	}

	public PascalUnicodeDataType(DataTypeManager dtm) {
		super("PascalUnicode", // data type name
			"p_unicode", // mnemonic
			"P_UNICODE", // default label
			"P_UNI", // default label prefix
			"pu", // default abbrev label prefix
			"String (Pascal UTF-16 64k)", // description
			CharsetInfo.UTF16, // charset
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
		return new PascalUnicodeDataType(dtm);
	}
}
