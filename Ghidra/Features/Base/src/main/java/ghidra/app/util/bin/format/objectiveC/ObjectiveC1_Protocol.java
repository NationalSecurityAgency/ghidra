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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_Protocol implements StructConverter {
	public final static String NAME = "objc_protocol";
	public final static int SIZEOF = 20;

	private ObjectiveC1_State _state;
	private long _index;

	private int isa;
	private String name;
	private ObjectiveC1_ProtocolList protocolList;
	private ObjectiveC1_ProtocolMethodList instanceMethods;
	private ObjectiveC1_ProtocolMethodList classMethods;

	public ObjectiveC1_Protocol(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		isa             = reader.readNextInt();
		name            = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		protocolList    = new ObjectiveC1_ProtocolList(state, reader.clone(reader.readNextInt()));
		instanceMethods = new ObjectiveC1_ProtocolMethodList(state, reader.clone(reader.readNextInt()), ObjectiveC_MethodType.INSTANCE);
		classMethods    = new ObjectiveC1_ProtocolMethodList(state, reader.clone(reader.readNextInt()), ObjectiveC_MethodType.CLASS);
	}

	public int getIsa() {
		return isa;
	}

	public String getName() {
		return name;
	}

	public ObjectiveC1_ProtocolList getProtocolList() {
		return protocolList;
	}

	public ObjectiveC1_ProtocolMethodList getInstanceMethods() {
		return instanceMethods;
	}

	public ObjectiveC1_ProtocolMethodList getClassMethods() {
		return classMethods;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "isa", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "name", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_ProtocolList.toGenericDataType(_state), _state.pointerSize), "protocolList", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_ProtocolMethodList.toGenericDataType(_state), _state.pointerSize), "instanceMethods", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_ProtocolMethodList.toGenericDataType(_state), _state.pointerSize), "classMethods", null);
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

		protocolList.applyTo();
		instanceMethods.applyTo();
		classMethods.applyTo();
	}

}
