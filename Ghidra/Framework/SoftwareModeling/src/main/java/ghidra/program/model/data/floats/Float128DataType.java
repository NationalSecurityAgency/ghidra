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

public class Float128DataType extends AbstractFloatDataType {

	static {
		// remap old byte-sized float to this bit-sized equivalent
		ClassTranslator.put(
			"ghidra.program.model.data.Float16DataType", Float128DataType.class.getName());
	}

	public static final Float128DataType dataType = new Float128DataType();

	public Float128DataType() {
		this(null);
	}

	public Float128DataType(DataTypeManager dtm) {
		super("float128", 16, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Float128DataType(dtm);
	}

}
