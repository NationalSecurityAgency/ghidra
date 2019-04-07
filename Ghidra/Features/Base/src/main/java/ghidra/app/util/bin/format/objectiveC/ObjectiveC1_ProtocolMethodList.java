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

public class ObjectiveC1_ProtocolMethodList implements StructConverter {
	public static final String NAME = "objc_protocol_method_list";

	private ObjectiveC1_State _state;
	private long _index;

	private int method_count;
	private List<ObjectiveC1_ProtocolMethod> method_list = new ArrayList<ObjectiveC1_ProtocolMethod>();

	ObjectiveC1_ProtocolMethodList(ObjectiveC1_State state, BinaryReader reader, ObjectiveC_MethodType methodType) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();
		if (_index == 0) {
			return;
		}

		method_count = reader.readNextInt();

		for (int i = 0 ; i < method_count ; ++i) {
			method_list.add(new ObjectiveC1_ProtocolMethod(state, reader, methodType));
		}
	}

	public int getMethodCount() {
		return method_count;
	}

	public List<ObjectiveC1_ProtocolMethod> getMethodList() {
		return method_list;
	}

	public static DataType toGenericDataType(ObjectiveC1_State state)
			throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "method_count", null);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+method_count+"_", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "method_count", null);
		if (method_count > 0) {
			DataType dt = method_list.get(0).toDataType();
			struct.add(new ArrayDataType(dt, method_count, dt.getLength()), "method_list", null);
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

		for (ObjectiveC1_ProtocolMethod method : method_list) {
			if (_state.monitor.isCancelled()) {
				break;
			}
			method.applyTo();
		}
	}

}
