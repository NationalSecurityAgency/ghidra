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
package ghidra.app.util.bin.format.objectiveC;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC1_ProtocolList implements StructConverter {
	public static final String NAME = "objc_protocol_list";

	private ObjectiveC1_State _state;
	private long _index;

	private ObjectiveC1_ProtocolList next;
	private int count;
	private List<ObjectiveC1_Protocol> protocols = new ArrayList<ObjectiveC1_Protocol>();

	ObjectiveC1_ProtocolList(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();
		if (_index == 0) {
			return;
		}

		next = new ObjectiveC1_ProtocolList(state, reader.clone( reader.readNextInt() ));

		count = reader.readNextInt();

		for (int i = 0 ; i < count ; ++i) {
			int protocolIndex = reader.readNextInt();
			long oldProtocolIndex = reader.getPointerIndex();
			reader.setPointerIndex(protocolIndex);
			protocols.add(new ObjectiveC1_Protocol(state, reader));
			reader.setPointerIndex(oldProtocolIndex);
		}
	}

	public ObjectiveC1_ProtocolList getNext() {
		return next;
	}

	public int getCount() {
		return count;
	}

	public List<ObjectiveC1_Protocol> getProtocols() {
		return protocols;
	}

	public static DataType toGenericDataType(ObjectiveC1_State state)
			throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(struct, state.pointerSize), "next", null);
		struct.add(DWORD, "count", null);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+count+"_", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(toGenericDataType(_state), _state.pointerSize), "next", null);
		struct.add(DWORD, "count", null);
		if (count > 0) {
			DataType dt = PointerDataType.getPointer(protocols.get(0).toDataType(), _state.pointerSize);
			struct.add(new ArrayDataType(dt, count, dt.getLength()), "protocols", null);
		}
		return struct;
	}

	public void applyTo() throws Exception {
		if (_index == 0) {
			return;
		}
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength()-1), false);
		_state.program.getListing().createData(address, dt);

		for (ObjectiveC1_Protocol protocol : protocols) {
			if (_state.monitor.isCancelled()) {
				break;
			}
			protocol.applyTo();
		}
	}
}
