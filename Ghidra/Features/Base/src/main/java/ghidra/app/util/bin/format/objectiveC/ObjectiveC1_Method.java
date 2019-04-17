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
import ghidra.program.model.data.*;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_Method extends ObjectiveC_Method {
	private String name;
	private String signature;
	private int address;

	ObjectiveC1_Method(ObjectiveC1_State state, BinaryReader reader, ObjectiveC_MethodType methodType) throws IOException {
		super(state, reader, methodType);

		name      = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		signature = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		address   = reader.readNextInt();
	}

	@Override
	public String getName() {
		return name;
	}
	@Override
	public String getTypes() {
		return signature;
	}
	@Override
	public long getImplementation() {
		return address & Conv.INT_MASK;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_method", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "method_name", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "method_types", null);
		struct.add(PointerDataType.getPointer(VOID,  _state.pointerSize), "method_imp", null);
		return struct;
	}

}
