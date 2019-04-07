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
 * Provides a definition of a {@code complex} built-in data type consisting of two 16 byte floating point
 * numbers in the IEEE 754 double precision format.
 */
public class Complex32DataType extends AbstractComplexDataType {

	public static final Complex32DataType dataType = new Complex32DataType();

	public Complex32DataType() {
		this(null);
	}

	public Complex32DataType(DataTypeManager dtm) {
		super("complex32", Float16DataType.dataType, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Complex32DataType(dtm);
	}
}
