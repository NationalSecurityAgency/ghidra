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
 * A fixed-length UTF-32 string {@link DataType}.
 * <p>
 */
public class Unicode32DataType extends AbstractStringDataType {

	public static final Unicode32DataType dataType = new Unicode32DataType();

	/**
	 * Constructs a new unicode dataType
	 */
	public Unicode32DataType() {
		this(null);
	}

	public Unicode32DataType(DataTypeManager dtm) {
		super("unicode32", // data type name
			"unicode32", // mnemonic
			"UNICODE", // default label
			"UNI", // default label prefix
			"u", // default abbrev label prefix
			"String (Fixed Length UTF-32 Unicode)", // description
			CharsetInfo.UTF32, // charset
			WideChar32DataType.dataType, // replacement data type
			StringLayoutEnum.FIXED_LEN, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Unicode32DataType(dtm);
	}
}
