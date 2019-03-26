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
package ghidra.app.util.bin.format.objectiveC;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_ProtocolMethod implements StructConverter {
	private static final String NAME = "objc_protocol_method";

	private ObjectiveC1_State _state;
	private ObjectiveC_MethodType _methodType;

	private String name;
	private String types;

	ObjectiveC1_ProtocolMethod(ObjectiveC1_State state, BinaryReader reader, ObjectiveC_MethodType methodType) throws IOException {
		this._state = state;
		this._methodType = methodType;

		name  = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		types = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
	}

	public String getName() {
		return name;
	}

	public String getTypes() {
		return types;
	}

	public ObjectiveC_MethodType getMethodType() {
		return _methodType;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "name", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "types", null);
		return struct;
	}

	void applyTo() {
	}
}
