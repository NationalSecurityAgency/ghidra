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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC2_InstanceVariable implements StructConverter {
	private ObjectiveC2_State _state;

	private long offset;
	private String name;
	private String type;
	private int alignment;
	private int size;

	public ObjectiveC2_InstanceVariable(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;

		if (state.is32bit) {
			offset = reader.readNextInt() & Conv.INT_MASK;
		}
		else {
			offset = reader.readNextLong();
		}

		long nameIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
		if (nameIndex > 0 && reader.isValidIndex(nameIndex)) {
			name      = reader.readAsciiString( nameIndex );
		}

		long typeIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
		if (typeIndex > 0 && reader.isValidIndex(typeIndex)) {
			type      = reader.readAsciiString( typeIndex );
		}

		alignment  = reader.readNextInt();
		size       = reader.readNextInt();
	}

	public long getOffset() {
		return offset;
	}

	public String getName() {
		return name;
	}

	public String getType() {
		return type;
	}

	public int getAlignment() {
		return alignment;
	}

	public int getSize() {
		return size;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("ivar_t", 0);
		if (_state.is32bit) {
			struct.add(new PointerDataType(DWORD), _state.pointerSize, "offset", null);
			struct.add(new PointerDataType(STRING), _state.pointerSize, "name", null);
			struct.add(new PointerDataType(STRING), _state.pointerSize, "type", null);
		}
		else {
			struct.add(new PointerDataType(QWORD), _state.pointerSize, "offset", null);
			struct.add(new PointerDataType(STRING), _state.pointerSize, "name", null);
			struct.add(new PointerDataType(STRING), _state.pointerSize, "type", null);
		}
		struct.add(DWORD, "alignment", null);
		struct.add(DWORD, "size", null);
		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo(Namespace namespace) throws Exception {
		if (getOffset() == 0) {
			return;
		}
		if (getName() == null && getName().length() == 0) {
			return;
		}
		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(getOffset());
		ObjectiveC1_Utilities.createSymbol(_state.program, namespace, getName(), address);
		_state.variableMap.put(address, this);
	}
}
