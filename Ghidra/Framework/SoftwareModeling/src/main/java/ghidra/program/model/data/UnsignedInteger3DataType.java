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

import ghidra.util.classfinder.ClassTranslator;

public class UnsignedInteger3DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined UnsignedInteger3DataType instance.*/
	public final static UnsignedInteger3DataType dataType = new UnsignedInteger3DataType();

	static {
		ClassTranslator.put("ghidra.program.model.data.ThreeByteDataType",
			UnsignedInteger3DataType.class.getName());
	}

	public UnsignedInteger3DataType() {
		this(null);
	}

	public UnsignedInteger3DataType(DataTypeManager dtm) {
		super("uint3", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned 3-Byte Integer)";
	}

	@Override
	public int getLength() {
		return 3;
	}

	@Override
	public Integer3DataType getOppositeSignednessDataType() {
		return Integer3DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedInteger3DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedInteger3DataType(dtm);
	}
}
