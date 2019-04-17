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
 * A fixed-length UTF-8 string {@link DataType}.
 * <p>
 */
public class StringUTF8DataType extends AbstractStringDataType {
	public static final StringUTF8DataType dataType = new StringUTF8DataType();

	public StringUTF8DataType() {
		this(null);
	}

	public StringUTF8DataType(DataTypeManager dtm) {
		super("string-utf8", // data type name
			"utf8", // mnemonic
			"STRING", // default label
			"STR", // default label prefix
			"s", // default abbrev label prefix
			"String (Fixed Length UTF-8 Unicode)", // description
			CharsetInfo.UTF8, // charset
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
		return new StringUTF8DataType(dtm);
	}

}
