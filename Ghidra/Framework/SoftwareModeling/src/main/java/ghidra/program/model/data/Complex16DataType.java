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
 * Provides a definition of a {@code complex} built-in data type consisting of two 8 byte floating point
 * numbers in the IEEE 754 double precision format.
 */
public class Complex16DataType extends AbstractComplexDataType {

	public static final Complex16DataType dataType = new Complex16DataType();

	public Complex16DataType() {
		this(null);
	}

	public Complex16DataType(DataTypeManager dtm) {
		super("complex16", Float8DataType.dataType, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Complex16DataType(dtm);
	}
}
