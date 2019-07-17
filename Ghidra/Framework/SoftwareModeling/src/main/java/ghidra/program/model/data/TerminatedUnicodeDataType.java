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
 * A null-terminated string {@link DataType} with a UTF-16 {@link CharsetSettingsDefinition charset}.
 * <p>
 *
 * NOTE: TerminatedUnicodeDataType class was renamed to TerminatedUnicodeStringDataType to
 * address problem where this factory data-type may have previously been added to
 * composites.
 */
public class TerminatedUnicodeDataType extends AbstractStringDataType {

	public static final TerminatedUnicodeDataType dataType = new TerminatedUnicodeDataType();

	public TerminatedUnicodeDataType() {
		this(null);
	}

	public TerminatedUnicodeDataType(DataTypeManager dtm) {
		super("TerminatedUnicode", // data type name
			"unicode", // mnemonic
			DEFAULT_UNICODE_LABEL,// default label
			DEFAULT_UNICODE_LABEL_PREFIX, // default label prefix
			DEFAULT_UNICODE_ABBREV_PREFIX, // default abbrev label prefix
			"String (Null Terminated UTF-16 Unicode)", // description
			CharsetInfo.UTF16, // charset
			WideChar16DataType.dataType, // replacement data type
			StringLayoutEnum.NULL_TERMINATED_UNBOUNDED, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new TerminatedUnicodeDataType(dtm);
	}
}
