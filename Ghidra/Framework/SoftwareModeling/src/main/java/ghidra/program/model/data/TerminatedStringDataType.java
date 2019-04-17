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
 * A null-terminated string {@link DataType} with a user setable
 * {@link CharsetSettingsDefinition charset} (default ASCII).
 * <p>
 */
public class TerminatedStringDataType extends AbstractStringDataType {

	public static final TerminatedStringDataType dataType = new TerminatedStringDataType();

	public TerminatedStringDataType() {
		this(null);
	}

	public TerminatedStringDataType(DataTypeManager dtm) {
		super("TerminatedCString", // data type name
			"ds", // mnemonic
			"STRING", // default label
			"STR", // default label prefix
			"s", // default abbrev label prefix
			"String (Null Terminated)", // description
			USE_CHARSET_DEF_DEFAULT, // charset
			CharDataType.dataType, // replacement data type
			StringLayoutEnum.NULL_TERMINATED_UNBOUNDED, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new TerminatedStringDataType(dtm);
	}
}
