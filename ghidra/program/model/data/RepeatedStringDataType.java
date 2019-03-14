/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
 * Some number of repeated strings.  Each string can be of variable length.
 * 
 * The data structure looks like this:
 * 
 *    RepeatedStringDT
 *        numberOfStrings = N
 *        String1
 *        String2
 *        ...
 *        StringN
 */
public class RepeatedStringDataType extends RepeatCountDataType {

	private static DataType datatype = new StringDataType();

	public RepeatedStringDataType() {
		this(null);
	}

	public RepeatedStringDataType(DataTypeManager dtm) {
		super(datatype, null, "RepString", dtm);
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return "Repeated String";
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RepeatedStringDataType(dtm);
	}

}
