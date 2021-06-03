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

import ghidra.util.classfinder.ClassTranslator;

/**
 * A fixed-length string {@link DataType} with a user setable
 * {@link CharsetSettingsDefinition charset} (default ASCII).
 * <p>
 * All string data types:
 * <ul>
 * <li>{@link StringDataType} - this type, fixed length, user settable charset.
 * <li>{@link StringUTF8DataType} - fixed length UTF-8 string.
 * <li>{@link TerminatedStringDataType} - terminated and unbounded string, user settable charset.
 * <li>{@link TerminatedUnicodeDataType} - terminated and unbounded UTF-16 string.
 * <li>{@link TerminatedUnicode32DataType} - terminated and unbounded UTF-32 string.
 * <li>{@link PascalString255DataType} - length-prefixed string (limited to 255 chars), user settable charset.
 * <li>{@link PascalStringDataType} - length-prefixed string (limited to 64k), user settable charset.
 * <li>{@link PascalUnicodeDataType} - length-prefixed UTF-16 (limited to 64k).
 * <li>{@link UnicodeDataType} - fixed length UTF-16 string.
 * <li>{@link Unicode32DataType} - fixed length UTF-32 string.
 * </ul>
 * <p>
 * The following settings are supported by all string types on the data instance:
 * <ul>
 * <li> {@link TranslationSettingsDefinition} - controls display of string values that have been
 * translated to english.
 * <li> {@link RenderUnicodeSettingsDefinition} - controls display of non-ascii Unicode characters.
 * </ul>
 */
public class StringDataType extends AbstractStringDataType {
	static {
		ClassTranslator.put("ghidra.app.plugin.data.MBCSDataType", StringDataType.class.getName());
		ClassTranslator.put("ghidra.app.plugin.core.data.mbcs.MBCSDataType",
			StringDataType.class.getName());
	}

	public static final StringDataType dataType = new StringDataType();

	public StringDataType() {
		this(null);
	}

	public StringDataType(DataTypeManager dtm) {
		super("string", // data type name
			"ds", // mnemonic
			"STRING", // default label
			"STR", // default label prefix
			"s", // default abbrev label prefix
			"String (fixed length)", // description
			USE_CHARSET_DEF_DEFAULT, // charset
			CharDataType.dataType, // replacement data type
			StringLayoutEnum.FIXED_LEN, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new StringDataType(dtm);
	}

}
