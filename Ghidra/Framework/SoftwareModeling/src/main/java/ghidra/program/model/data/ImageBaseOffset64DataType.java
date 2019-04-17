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

import ghidra.util.classfinder.*;

public class ImageBaseOffset64DataType extends AbstractImageBaseOffsetDataType {
	static {
		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset64",
			ImageBaseOffset64DataType.class.getName());
	}

	private static DataType datatype = QWordDataType.dataType;

	public ImageBaseOffset64DataType() {
		this(null);
	}

	public ImageBaseOffset64DataType(DataTypeManager dtm) {
		super(null, generateName(datatype), dtm);
	}

	@Override
	DataType getScalarDataType() {
		return datatype;
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new ImageBaseOffset64DataType(dtm);
	}

}
