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
 * Provides a definition of a Float within a program.
 */
public class FloatDataType extends AbstractFloatDataType {

	public static final FloatDataType dataType = new FloatDataType();

	/**
	 * Creates a Float data type.
	 */
	public FloatDataType() {
		this(null);
	}

	public FloatDataType(DataTypeManager dtm) {
		super("float", getDataOrganization(dtm).getFloatSize(), dtm);
	}

	@Override
	protected String buildDescription() {
		return "Compiler-defined 'float' " + super.buildDescription();
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new FloatDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return null; // Standard C primitive
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

}
