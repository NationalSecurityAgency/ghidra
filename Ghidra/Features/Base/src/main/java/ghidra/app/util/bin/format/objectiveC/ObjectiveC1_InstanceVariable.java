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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_InstanceVariable implements StructConverter {
	private ObjectiveC1_State _state;
	private long _index;

	private String name;
	private String type;
	private int offset;

	ObjectiveC1_InstanceVariable(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		name = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		type = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		offset = reader.readNextInt();
	}

	public String getName() {
		return name;
	}

	public String getType() {
		return type;
	}

	public int getOffset() {
		return offset;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_ivar", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "ivar_name", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "ivar_type", null);
		struct.add(DWORD, "ivar_offset", null);
		return struct;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength()-1), false);
		_state.program.getListing().createData(address, dt);
	}
}
