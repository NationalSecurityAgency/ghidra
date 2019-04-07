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
 * A fixed-length UTF-16 string {@link DataType}.
 * <p>
 */
public class UnicodeDataType extends AbstractStringDataType {

	public static final UnicodeDataType dataType = new UnicodeDataType();

	public UnicodeDataType() {
		this(null);
	}

	public UnicodeDataType(DataTypeManager dtm) {
		super("unicode", // data type name
			"unicode", // mnemonic
			"UNICODE", // default label
			"UNI", // default label prefix
			"u", // default abbrev label prefix
			"String (Fixed Length UTF-16 Unicode)", // description
			CharsetInfo.UTF16, // charset
			WideChar16DataType.dataType, // replacement data type
			StringLayoutEnum.FIXED_LEN, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnicodeDataType(dtm);
	}
}
