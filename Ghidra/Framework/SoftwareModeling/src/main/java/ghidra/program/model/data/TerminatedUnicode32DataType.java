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
 * A null-terminated UTF-32 string {@link DataType}.
 * <p>
 */
public class TerminatedUnicode32DataType extends AbstractStringDataType {

	public static final TerminatedUnicode32DataType dataType = new TerminatedUnicode32DataType();

	public TerminatedUnicode32DataType() {
		this(null);
	}

	public TerminatedUnicode32DataType(DataTypeManager dtm) {
		super("TerminatedUnicode32", // data type name
			"unicode32", // mnemonic
			"UNICODE", // default label
			"UNI", // default label prefix
			"u", // default abbrev label prefix
			"String (Null Terminated UTF-32 Unicode)", // description
			CharsetInfo.UTF32, // charset
			WideChar32DataType.dataType, // replacement data type
			StringLayoutEnum.NULL_TERMINATED_UNBOUNDED, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new TerminatedUnicode32DataType(dtm);
	}
}
