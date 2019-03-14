/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.objc2;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC2_Property implements StructConverter {
	private ObjectiveC2_State _state;

	private String name;
	private String attributes;

	public ObjectiveC2_Property(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;

		long nameIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
		name  = reader.readAsciiString(nameIndex);

		long attributesIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
		attributes  = reader.readAsciiString(attributesIndex);
	}

	public String getName() {
		return name;
	}

	public String getAttributes() {
		return attributes;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("objc_property", 0);

		struct.add(new PointerDataType(ASCII), _state.pointerSize, "name", null);
		struct.add(new PointerDataType(ASCII), _state.pointerSize, "name", null);

		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo(Namespace namespace) {
	}
}
