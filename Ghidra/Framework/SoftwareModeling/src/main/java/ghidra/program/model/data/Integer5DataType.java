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

public class Integer5DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined Integer5DataType instance.*/
	public final static Integer5DataType dataType = new Integer5DataType();

	public Integer5DataType() {
		this(null);
	}

	public Integer5DataType(DataTypeManager dtm) {
		super("int5", true, dtm);
	}

	@Override
	public String getDescription() {
		return "Signed 5-Byte Integer";
	}

	@Override
	public int getLength() {
		return 5;
	}

	@Override
	public UnsignedInteger5DataType getOppositeSignednessDataType() {
		return UnsignedInteger5DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Integer5DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Integer5DataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
