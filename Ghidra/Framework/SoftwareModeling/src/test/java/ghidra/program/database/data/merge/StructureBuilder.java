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
package ghidra.program.database.data.merge;

import ghidra.program.model.data.*;

/**
 * Convenience class for building structures in tests.
 */
public class StructureBuilder {
	Structure result;
	private DataTypeManager dtm;

	public StructureBuilder(String name, int size) {
		this(null, name, size);
	}

	public StructureBuilder(DataTypeManager dtm, String name, int size) {
		this.dtm = dtm;
		result = new StructureDataType(name, size, dtm);
	}

	public StructureBuilder add(int offset, DataType dt, String name) {
		result.replaceAtOffset(offset, dt, -1, name, null);
		return this;
	}

	public StructureBuilder add(int offset, DataType dt, String name, String comment) {
		result.replaceAtOffset(offset, dt, -1, name, comment);
		return this;
	}

	public StructureBuilder bitField(int offset, int byteWidth, int bitStart, int bitEnd,
			String name, String comment) throws InvalidDataTypeException {
		result.insertBitFieldAt(offset, byteWidth, bitStart, new IntegerDataType(),
			bitEnd - bitStart + 1,
			name, comment);
		return this;
	}

	public StructureBuilder bitField(int offset, int byteWidth, int bitStart, int bitEnd,
			String name) throws InvalidDataTypeException {
		result.insertBitFieldAt(offset, byteWidth, bitStart, new IntegerDataType(),
			bitEnd - bitStart + 1,
			name, null);
		return this;
	}

	public StructureBuilder description(String description) {
		result.setDescription(description);
		return this;
	}

	public Structure build() {
		return result;
	}

	public Structure buildDb() {
		return (Structure) dtm.resolve(result, null);
	}

	public StructureBuilder pack() {
		result.setPackingEnabled(true);
		return this;
	}

}
