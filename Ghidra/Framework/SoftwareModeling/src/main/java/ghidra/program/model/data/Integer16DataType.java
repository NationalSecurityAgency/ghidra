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
 * A fixed size 16 byte signed integer (commonly referred to in C as int128_t)
 */
public class Integer16DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined Integer16DataType instance.*/
	public final static Integer16DataType dataType = new Integer16DataType();

	public Integer16DataType() {
		this(null);
	}

	public Integer16DataType(DataTypeManager dtm) {
		super("int16", true, dtm);
	}

	@Override
	public String getDescription() {
		return "Signed 16-Byte Integer";
	}

	@Override
	public int getLength() {
		return 16;
	}

	@Override
	public UnsignedInteger16DataType getOppositeSignednessDataType() {
		return UnsignedInteger16DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Integer16DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Integer16DataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
