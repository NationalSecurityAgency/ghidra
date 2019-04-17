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
 * Provides a definition of a {@code complex} built-in data type consisting of two floating point
 * numbers in the IEEE 754 double precision format.
 * <P>
 * The size of the floating point numbers is determined the the program's data organization as defined
 * by the language/compiler spec
 */
public class FloatComplexDataType extends AbstractComplexDataType {

	public static final FloatComplexDataType dataType = new FloatComplexDataType();

	public FloatComplexDataType() {
		this(null);
	}

	public FloatComplexDataType(DataTypeManager dtm) {
		super("floatcomplex", FloatDataType.dataType, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new FloatComplexDataType(dtm);
	}
}
