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

public class UnsignedInteger7DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined UnsignedInteger7DataType instance.*/
	public final static UnsignedInteger7DataType dataType = new UnsignedInteger7DataType();

	public UnsignedInteger7DataType() {
		this(null);
	}

	public UnsignedInteger7DataType(DataTypeManager dtm) {
		super("uint7", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned 7-Byte Integer";
	}

	@Override
	public int getLength() {
		return 7;
	}

	@Override
	public Integer7DataType getOppositeSignednessDataType() {
		return Integer7DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedInteger7DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedInteger7DataType(dtm);
	}
}
