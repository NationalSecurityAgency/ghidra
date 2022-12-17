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

public class UnsignedInteger1DataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined UnsignedInteger1DataType instance.*/
	public final static UnsignedInteger1DataType dataType = new UnsignedInteger1DataType();

	static {
		ClassTranslator.put("ghidra.program.model.data.ThreeByteDataType",
			UnsignedInteger1DataType.class.getName());
	}

	public UnsignedInteger1DataType() {
		this(null);
	}

	public UnsignedInteger1DataType(DataTypeManager dtm) {
		super("uint1", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned 1-Byte Integer)";
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public Integer1DataType getOppositeSignednessDataType() {
		return Integer1DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedInteger1DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedInteger1DataType(dtm);
	}
}
