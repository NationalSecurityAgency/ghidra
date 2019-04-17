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

public class Float8DataType extends AbstractFloatDataType {

	public static final Float8DataType dataType = new Float8DataType();

	public Float8DataType() {
		this(null);
	}

	public Float8DataType(DataTypeManager dtm) {
		super("float8", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Float8DataType(dtm);
	}

	@Override
	public int getLength() {
		return 8;
	}

}
