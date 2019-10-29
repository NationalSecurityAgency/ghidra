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

public class Integer7DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined Integer7DataType instance.*/
	public final static Integer7DataType dataType = new Integer7DataType();

	public Integer7DataType() {
		this(null);
	}

	public Integer7DataType(DataTypeManager dtm) {
		super("int7", true, dtm);
	}

	@Override
	public String getDescription() {
		return "Signed 7-Byte Integer";
	}

	@Override
	public int getLength() {
		return 7;
	}

	@Override
	public UnsignedInteger7DataType getOppositeSignednessDataType() {
		return UnsignedInteger7DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Integer7DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Integer7DataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
