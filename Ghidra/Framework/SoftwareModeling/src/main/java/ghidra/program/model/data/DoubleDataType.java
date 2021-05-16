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
 * Provides a definition of a Double within a program.
 */
public class DoubleDataType extends AbstractFloatDataType {

	public static final DoubleDataType dataType = new DoubleDataType();

	/**
	 * Creates a Double data type.
	 */
	public DoubleDataType() {
		this(null);
	}

	public DoubleDataType(DataTypeManager dtm) {
		super("double", dtm);
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new DoubleDataType(dtm);
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public int getLength() {
		return getDataOrganization().getDoubleSize();
	}

}
