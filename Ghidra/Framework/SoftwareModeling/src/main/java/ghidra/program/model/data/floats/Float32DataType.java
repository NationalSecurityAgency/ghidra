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
package ghidra.program.model.data.floats;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.classfinder.ClassTranslator;

public class Float32DataType extends AbstractFloatDataType {

	static {
		// remap old byte-sized float to this bit-sized equivalent
		ClassTranslator.put(
			"ghidra.program.model.data.Float4DataType", Float32DataType.class.getName());
	}

	public static final Float32DataType dataType = new Float32DataType();

	public Float32DataType() {
		this(null);
	}

	public Float32DataType(DataTypeManager dtm) {
		super("float32", 4, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Float32DataType(dtm);
	}

}
