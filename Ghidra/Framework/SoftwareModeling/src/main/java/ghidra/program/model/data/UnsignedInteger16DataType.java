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
 * A fixed size 16 byte unsigned integer (commonly referred to in C as uint128_t)
 */
public class UnsignedInteger16DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined UnsignedInteger16DataType instance.*/
	public final static UnsignedInteger16DataType dataType = new UnsignedInteger16DataType();

	public UnsignedInteger16DataType() {
		this(null);
	}

	public UnsignedInteger16DataType(DataTypeManager dtm) {
		super("uint16", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned 16-Byte Integer";
	}

	@Override
	public int getLength() {
		return 16;
	}

	@Override
	public Integer16DataType getOppositeSignednessDataType() {
		return Integer16DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedInteger16DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedInteger16DataType(dtm);
	}
}
