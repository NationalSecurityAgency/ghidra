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

public class UnsignedInteger5DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined UnsignedInteger5DataType instance.*/
	public final static UnsignedInteger5DataType dataType = new UnsignedInteger5DataType();

	public UnsignedInteger5DataType() {
		this(null);
	}

	public UnsignedInteger5DataType(DataTypeManager dtm) {
		super("uint5", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned 5-Byte Integer";
	}

	@Override
	public int getLength() {
		return 5;
	}

	@Override
	public Integer5DataType getOppositeSignednessDataType() {
		return Integer5DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedInteger5DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedInteger5DataType(dtm);
	}
}
